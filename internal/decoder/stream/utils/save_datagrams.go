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

func SaveDatagramConversation(source core.FragmentSource, ident string, first time.Time, transport gopacket.Flow, communityID string) error {
	if source.Count() == 0 {
		return nil
	}
	limit := decoderconfig.Instance.HarvesterBannerSize
	var banner []byte
	var size int64
	if err := source.Walk(func(fragment core.DataFragment) bool {
		data := fragment.Raw()
		size += int64(len(data))
		if len(banner) < limit {
			banner = append(banner, data[:min(len(data), limit-len(banner))]...)
		}
		return true
	}); err != nil {
		return err
	}
	if size == 0 {
		return nil
	}
	secret.RunHarvesters(banner, transport, ident, first, communityID)
	if DeviceEnricher != nil {
		if err := source.Walk(func(fragment core.DataFragment) bool {
			for _, result := range discovery.RunDiscovery(fragment.Raw(), transport, ident, fragment.CaptureInfo().Timestamp, fragment.Network().Src().String()) {
				DeviceEnricher(result.SourceIP, result.Hostnames, result.DeviceTypes, result.Roles, result.OS)
			}
			return true
		}); err != nil {
			return err
		}
	}
	if !decoderconfig.Instance.SaveConns {
		return nil
	}
	if _, err := SaveSourceEvidence(decoderconfig.Instance.Out, "UDP", source, ident, first, communityID); err != nil {
		return err
	}
	root := filepath.Join(decoderconfig.Instance.Out, "udp", getServiceName(banner, transport, "UDP"))
	if err := os.MkdirAll(root, defaults.DirectoryPermission); err != nil {
		return err
	}
	base := filepath.Join(root, filepath.Clean(path.Base(utils.CleanIdent(ident)))+binaryFileExtension)
	f, err := os.OpenFile(base, os.O_CREATE|os.O_WRONLY|os.O_APPEND|os.O_SYNC, defaults.FilePermission)
	if err != nil {
		return err
	}
	defer f.Close()
	w := bufio.NewWriterSize(f, 4096)
	var writeErr error
	if err = source.Walk(func(fragment core.DataFragment) bool { _, writeErr = w.Write(fragment.Raw()); return writeErr == nil }); err != nil {
		return err
	}
	if writeErr != nil {
		return writeErr
	}
	err = w.Flush()
	err = errors.Join(err, f.Sync(), f.Close())
	if err == nil {
		Stats.Lock()
		Stats.SavedUDPConnections++
		Stats.Unlock()
	}
	return err
}
