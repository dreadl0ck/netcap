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
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/mgutz/ansi"
	"go.uber.org/zap"

	decoderconfig "github.com/dreadl0ck/netcap/decoder/config"
	"github.com/dreadl0ck/netcap/decoder/core"
	"github.com/dreadl0ck/netcap/decoder/stream/credentials"
	"github.com/dreadl0ck/netcap/defaults"
	"github.com/dreadl0ck/netcap/reassembly"
	"github.com/dreadl0ck/netcap/utils"
)

// TODO: remove dups
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

// SaveConversation will save TCP / UDP conversations to disk
// this also invokes the harvesters on the conversation banner
func SaveConversation(proto string, conversation core.DataFragments, ident string, firstPacket time.Time, transport gopacket.Flow) error {
	// prevent processing zero bytes
	if len(conversation) == 0 || conversation.Size() == 0 {
		return nil
	}

	// fmt.Println("saving conv", conversation.size(), ident)

	banner := createBannerFromConversation(conversation)
	credentials.RunHarvesters(banner, transport, ident, firstPacket)

	if !decoderconfig.Instance.SaveConns {
		return nil
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

	if proto == protoTCP {
		// create the buffer with the entire conversation
		for _, d := range conversation {

			if d.Direction() == reassembly.TCPDirClientToServer {
				_, _ = w.WriteString(ansi.Red)
				_, _ = w.Write(d.Raw())
				_, _ = w.WriteString(ansi.Reset)
			} else {
				_, _ = w.WriteString(ansi.Blue)
				_, _ = w.Write(d.Raw())
				_, _ = w.WriteString(ansi.Reset)
			}

			if decoderconfig.Instance.Debug {
				var ts string
				if d.Context() != nil {
					ts = "\n[" + d.Context().GetCaptureInfo().Timestamp.String() + "]\n"
				}

				_, _ = w.WriteString(ts)
			}
		}
	} else { // UDP
		clientTransport := conversation[0].Transport()
		for _, d := range conversation {
			if d.Transport() == clientTransport {
				// client
				_, _ = w.WriteString(ansi.Red)
				_, _ = w.Write(d.Raw())
				_, _ = w.WriteString(ansi.Reset)
			} else {
				// server
				_, _ = w.WriteString(ansi.Blue)
				_, _ = w.Write(d.Raw())
				_, _ = w.WriteString(ansi.Reset)
			}
			if decoderconfig.Instance.Debug {
				_, _ = w.WriteString("\n[" + d.CaptureInfo().Timestamp.String() + "]\n")
			}
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
	// prevent processing zero bytes
	if len(conversation) == 0 {
		return nil
	}

	// Calculate total size
	var totalSize int
	for _, d := range conversation {
		totalSize += len(d.Raw())
	}
	if totalSize == 0 {
		return nil
	}

	if !decoderconfig.Instance.SaveConns {
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
		reassemblyLog.Warn("failed to create directory",
			zap.String("path", root),
			zap.Int("perm", defaults.DirectoryPermission),
		)
	}

	base = path.Join(root, base)

	reassemblyLog.Info("saveNetworkConversation", zap.String("base", base), zap.String("protocol", protocol))

	Stats.Lock()
	Stats.SavedNetworkConnections++
	Stats.Unlock()

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

	// Write conversation data with direction colors
	clientNetwork := conversation[0].Network()
	for _, d := range conversation {
		if d.Network() == clientNetwork {
			// client (initiator)
			_, _ = w.WriteString(ansi.Red)
			_, _ = w.Write(d.Raw())
			_, _ = w.WriteString(ansi.Reset)
		} else {
			// server (responder)
			_, _ = w.WriteString(ansi.Blue)
			_, _ = w.Write(d.Raw())
			_, _ = w.WriteString(ansi.Reset)
		}
		if decoderconfig.Instance.Debug {
			_, _ = w.WriteString("\n[" + d.CaptureInfo().Timestamp.String() + "]\n")
		}
	}

	err = w.Flush()
	if err != nil {
		reassemblyLog.Info("failed to flush buffer",
			zap.String("ident", ident),
			zap.String("protocol", protocol),
			zap.String("base", base),
		)
	}

	err = f.Sync()
	if err != nil {
		reassemblyLog.Info("failed to sync file",
			zap.String("ident", ident),
			zap.String("protocol", protocol),
			zap.String("base", base),
		)
	}

	// close file
	err = f.Close()
	if err != nil {
		reassemblyLog.Error(
			"failed to close network conversation file",
			zap.String("path", base),
			zap.Error(err),
		)
	} else {
		reassemblyLog.Info("saved network conversation",
			zap.String("ident", ident),
			zap.String("protocol", protocol),
			zap.String("base", base),
		)
	}

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
