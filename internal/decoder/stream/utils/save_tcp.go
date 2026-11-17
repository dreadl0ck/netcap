package utils

import (
	"bufio"
	"errors"
	"os"
	"path"
	"path/filepath"
	"time"

	"github.com/dreadl0ck/netcap/defaults"
	decoderconfig "github.com/dreadl0ck/netcap/internal/decoder/config"
	"github.com/dreadl0ck/netcap/internal/decoder/core"
	"github.com/dreadl0ck/netcap/internal/decoder/stream/discovery"
	"github.com/dreadl0ck/netcap/internal/decoder/stream/secret"
	"github.com/dreadl0ck/netcap/internal/utils"
	"github.com/gopacket/gopacket"
)

func SaveTCPConversation(source core.FragmentSource, ident string, first time.Time, transport gopacket.Flow, communityID string) error {
	if source.Count() == 0 {
		return nil
	}
	limit := max(0, decoderconfig.Instance.HarvesterBannerSize)
	var banner []byte
	var sourceIP string
	hasBytes, discarded, blocked := false, false, false
	if err := source.Walk(func(fragment core.DataFragment) bool {
		if sourceIP == "" {
			sourceIP = fragment.Network().Src().String()
		}
		if data, ok := fragment.(*core.StreamData); ok {
			discarded = discarded || data.DiscardedBytes > 0
			blocked = blocked || data.SkippedBytes != 0 || data.DiscardedBytes > 0
		}
		raw := fragment.Raw()
		hasBytes = hasBytes || len(raw) > 0
		if !blocked && len(banner) < limit {
			banner = append(banner, raw[:min(len(raw), limit-len(banner))]...)
		}
		return !hasBytes || (!blocked && len(banner) < limit)
	}); err != nil {
		return err
	}
	if !hasBytes {
		if discarded && decoderconfig.Instance.SaveConns {
			_, err := SaveSourceEvidence(decoderconfig.Instance.Out, "TCP", source, ident, first, communityID)
			return err
		}
		return nil
	}
	secret.RunHarvesters(banner, transport, ident, first, communityID)
	if DeviceEnricher != nil && sourceIP != "" {
		for _, result := range discovery.RunDiscovery(banner, transport, ident, first, sourceIP) {
			DeviceEnricher(result.SourceIP, result.Hostnames, result.DeviceTypes, result.Roles, result.OS)
		}
	}
	if !decoderconfig.Instance.SaveConns {
		return nil
	}
	if _, err := SaveSourceEvidence(decoderconfig.Instance.Out, "TCP", source, ident, first, communityID); err != nil {
		return err
	}
	root := filepath.Join(decoderconfig.Instance.Out, "tcp", getServiceName(banner, transport, "TCP"))
	if err := os.MkdirAll(root, defaults.DirectoryPermission); err != nil {
		return err
	}
	base := filepath.Join(root, filepath.Clean(path.Base(utils.CleanIdent(ident)))+binaryFileExtension)
	file, err := os.OpenFile(base, os.O_CREATE|os.O_WRONLY|os.O_APPEND|os.O_SYNC, defaults.FilePermission)
	if err != nil {
		return err
	}
	defer file.Close()
	writer := bufio.NewWriterSize(file, 4096)
	var writeErr error
	if err := source.Walk(func(fragment core.DataFragment) bool {
		_, writeErr = writer.Write(fragment.Raw())
		return writeErr == nil
	}); err != nil {
		return err
	}
	if writeErr != nil {
		return writeErr
	}
	err = errors.Join(writer.Flush(), file.Sync(), file.Close())
	if err == nil {
		Stats.Lock()
		Stats.SavedTCPConnections++
		Stats.Unlock()
	}
	return err
}
