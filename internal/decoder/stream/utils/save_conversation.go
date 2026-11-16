/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package utils

import (
	"bufio"
	"errors"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/gopacket/gopacket"
	"go.uber.org/zap"

	"github.com/dreadl0ck/netcap/defaults"
	decoderconfig "github.com/dreadl0ck/netcap/internal/decoder/config"
	"github.com/dreadl0ck/netcap/internal/decoder/core"
	"github.com/dreadl0ck/netcap/internal/decoder/stream/discovery"
	"github.com/dreadl0ck/netcap/internal/decoder/stream/secret"
	"github.com/dreadl0ck/netcap/internal/reassembly"
	"github.com/dreadl0ck/netcap/internal/utils"
)

// DeviceEnricher is a callback function to enrich a device profile by IP.
// Set by the collector during initialization to avoid circular imports.
var DeviceEnricher func(ip string, hostnames, deviceTypes, roles []string, os string)

const (
	binaryFileExtension = ".bin"
	protoTCP            = "TCP"
	protoUDP            = "UDP"
	protoNetwork        = "network"
)

// NetworkDataFragment represents a single network-layer packet fragment
// This interface allows the network package to pass data without circular imports
type NetworkDataFragment interface {
	Raw() []byte
	CaptureInfo() gopacket.CaptureInfo
	Network() gopacket.Flow
	Direction() reassembly.TCPFlowDirection
}

// NetworkDataFragments is a slice of network data fragments
type NetworkDataFragments []NetworkDataFragment

type NetworkFragmentSource interface {
	Walk(func(NetworkDataFragment) bool) error
}

func (n NetworkDataFragments) Walk(yield func(NetworkDataFragment) bool) error {
	for _, fragment := range n {
		if !yield(fragment) {
			break
		}
	}
	return nil
}

// SaveConversation will save TCP / UDP conversations to disk
// this also invokes the harvesters on the conversation banner
// The communityID parameter is the Corelight Community ID v1 for the connection,
// calculated once at the stream level and passed through to harvesters.
func SaveConversation(proto string, conversation core.DataFragments, ident string, firstPacket time.Time, transport gopacket.Flow, communityID string) error {
	// prevent processing zero bytes
	if len(conversation) == 0 {
		return nil
	}
	if conversation.Size() == 0 {
		if decoderconfig.Instance.SaveConns {
			for _, fragment := range conversation {
				if data, ok := fragment.(*core.StreamData); ok && data.DiscardedBytes > 0 {
					_, err := SaveStreamEvidence(decoderconfig.Instance.Out, proto, conversation, ident, firstPacket, communityID)
					return err
				}
			}
		}
		return nil
	}

	// fmt.Println("saving conv", conversation.size(), ident)

	banner := createBannerFromConversation(conversation)
	secret.RunHarvesters(banner, transport, ident, firstPacket, communityID)

	// Run network discovery extractors and enrich device profiles
	if DeviceEnricher != nil {
		observe := func(data []byte, srcIP string, at time.Time) {
			for _, r := range discovery.RunDiscovery(data, transport, ident, at, srcIP) {
				DeviceEnricher(r.SourceIP, r.Hostnames, r.DeviceTypes, r.Roles, r.OS)
			}
		}
		if proto == protoUDP {
			for _, fragment := range conversation {
				observe(fragment.Raw(), fragment.Network().Src().String(), fragment.CaptureInfo().Timestamp)
			}
		} else if srcIP := conversation.SourceIP(); srcIP != "" {
			observe(banner, srcIP, firstPacket)
		}
	}

	if !decoderconfig.Instance.SaveConns {
		return nil
	}
	if _, err := SaveStreamEvidence(decoderconfig.Instance.Out, proto, conversation, ident, firstPacket, communityID); err != nil {
		return err
	}

	var (
		typ = getServiceName(banner, transport, proto)

		// path for storing the data
		root = filepath.Join(decoderconfig.Instance.Out, strings.ToLower(proto), typ)

		// file basename
		base = filepath.Clean(path.Base(utils.CleanIdent(ident))) + binaryFileExtension
	)

	// make sure root path exists
	err := os.MkdirAll(root, defaults.DirectoryPermission)
	if err != nil {
		reassemblyLog.Warn("failed to create directory",
			zap.String("path", root),
			zap.Int("perm", defaults.DirectoryPermission),
		)
	}

	base = path.Join(root, base)

	reassemblyLog.Info("saveConversation", zap.String("base", base))

	Stats.Lock()
	switch proto {
	case protoTCP:
		Stats.SavedTCPConnections++
	case protoUDP:
		Stats.SavedUDPConnections++
	}
	Stats.Unlock()

retry:
	// append to files
	f, err := os.OpenFile(base, os.O_CREATE|os.O_WRONLY|os.O_APPEND|os.O_SYNC, defaults.FilePermission)
	if err != nil {

		reassemblyLog.Error(
			"failed to create create path",
			zap.String("path", base),
			zap.Error(err),
		)

		// sleep and try again to handle too many open files error
		if strings.Contains(err.Error(), "too many open files") {
			time.Sleep(500 * time.Millisecond)

			goto retry
		}

		return err
	}

	// TODO: make buffer size configurable
	w := bufio.NewWriterSize(f, 4096)

	for _, d := range conversation {
		if _, err := w.Write(d.Raw()); err != nil {
			f.Close()
			return err
		}
	}

	err = w.Flush()
	if err != nil {
		reassemblyLog.Info("failed to flush buffer",
			zap.String("ident", ident),
			zap.String("proto", proto),
			zap.String("base", base),
			zap.String("proto", proto),
		)
	}

	err = f.Sync()
	if err != nil {
		reassemblyLog.Info("failed to sync file",
			zap.String("ident", ident),
			zap.String("proto", proto),
			zap.String("base", base),
			zap.String("proto", proto),
		)
	}

	// close file
	err = f.Close()
	if err != nil {
		reassemblyLog.Error(
			"failed to close conversation file",
			zap.String("path", base),
			zap.Error(err),
		)
	} else {
		reassemblyLog.Info("saved conversation",
			zap.String("ident", ident),
			zap.String("proto", proto),
			zap.String("base", base),
			zap.String("proto", proto),
		)
	}

	return nil
}

// SaveNetworkConversation will save network-layer conversations (ICMP, IGMP, GRE, etc.) to disk
// Protocol should be the network layer protocol name (e.g., "ICMPv4", "ICMPv6", "IGMP", "GRE")
func SaveNetworkConversation(protocol string, conversation NetworkDataFragments, ident string, firstPacket time.Time) error {
	return SaveNetworkSource(protocol, conversation, ident, firstPacket)
}

func SaveNetworkSource(protocol string, source NetworkFragmentSource, ident string, firstPacket time.Time) error {
	if !decoderconfig.Instance.SaveConns {
		return nil
	}
	hasPayload := false
	if err := source.Walk(func(d NetworkDataFragment) bool {
		hasPayload = len(d.Raw()) > 0
		return !hasPayload
	}); err != nil {
		return err
	}
	if !hasPayload {
		return nil
	}

	var (
		// path for storing the data: network/{protocol}/
		root = filepath.Join(decoderconfig.Instance.Out, protoNetwork, strings.ToLower(protocol))

		// file basename
		base = filepath.Clean(path.Base(utils.CleanIdent(ident))) + binaryFileExtension
	)

	// make sure root path exists
	err := os.MkdirAll(root, defaults.DirectoryPermission)
	if err != nil {
		return err
	}

	base = path.Join(root, base)

	reassemblyLog.Info("saveNetworkConversation", zap.String("base", base), zap.String("protocol", protocol))

retryNetwork:
	// append to files
	f, err := os.OpenFile(base, os.O_CREATE|os.O_WRONLY|os.O_APPEND|os.O_SYNC, defaults.FilePermission)
	if err != nil {
		reassemblyLog.Error(
			"failed to create path",
			zap.String("path", base),
			zap.Error(err),
		)

		// sleep and try again to handle too many open files error
		if strings.Contains(err.Error(), "too many open files") {
			time.Sleep(500 * time.Millisecond)
			goto retryNetwork
		}

		return err
	}

	// TODO: make buffer size configurable
	w := bufio.NewWriterSize(f, 4096)

	var writeErr error
	sourceErr := source.Walk(func(d NetworkDataFragment) bool {
		_, writeErr = w.Write(d.Raw())
		return writeErr == nil
	})
	if err := errors.Join(sourceErr, writeErr, w.Flush(), f.Sync(), f.Close()); err != nil {
		return err
	}
	Stats.Lock()
	Stats.SavedNetworkConnections++
	Stats.Unlock()
	return nil
}

func createBannerFromConversation(conversation core.DataFragments) []byte {
	var (
		banner    = make([]byte, 0, decoderconfig.Instance.HarvesterBannerSize)
		processed int
		totalSize = conversation.Size()
		maxSize   = decoderconfig.Instance.HarvesterBannerSize
	)

	// copy c.HarvesterBannerSize number of bytes from the raw conversation
	// to use for the credential harvesters
	// This limits the amount of data processed to prevent performance issues with large streams
	for _, d := range conversation {
		if fragment, ok := d.(*core.StreamData); ok && (fragment.SkippedBytes != 0 || fragment.DiscardedBytes > 0) {
			break
		}
		for _, b := range d.Raw() {
			if processed >= maxSize {
				break
			}

			processed++
			banner = append(banner, b)
		}
	}

	// Log when data is truncated for visibility into harvester behavior
	if totalSize > maxSize && decoderconfig.Instance.Debug {
		reassemblyLog.Debug("harvester banner truncated",
			zap.Int("totalSize", totalSize),
			zap.Int("processedSize", processed),
			zap.Int("maxSize", maxSize),
		)
	}

	return banner
}
