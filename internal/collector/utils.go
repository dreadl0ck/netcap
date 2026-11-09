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

package collector

import (
	"encoding/binary"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/gogo/protobuf/proto"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"
	"golang.org/x/net/bpf"
)

// handleRawPacketData takes ownership of data and reports whether the packet was admitted.
// Callers must not modify or reuse data.
func (c *Collector) handleRawPacketData(data []byte, ci *gopacket.CaptureInfo) bool {
	return c.handlePacket(c.decodeRawPacketData(data, ci))
}

func (c *Collector) decodeRawPacketData(data []byte, ci *gopacket.CaptureInfo) gopacket.Packet {
	// Determine the correct base layer for this packet.
	// For pcapng files with mixed link types, the per-packet link type
	// is stored in ci.AncillaryData[0].
	var baseLayer gopacket.Decoder = c.config.BaseLayer
	if len(ci.AncillaryData) > 0 {
		if lt, ok := ci.AncillaryData[0].(layers.LinkType); ok {
			if lt == 239 {
				order := inputPacketInfo(*ci).Order
				if order == nil {
					order = binary.NativeEndian
				}
				baseLayer = gopacket.DecodeFunc(func(data []byte, p gopacket.PacketBuilder) error { return decodeNFLOG(data, p, order) })
			} else if lt == layers.LinkTypeLinuxSLL2 {
				baseLayer = gopacket.DecodeFunc(decodeSLL2)
			} else if lt == 195 {
				baseLayer = gopacket.DecodeFunc(decodeIEEE802154FCS)
			} else if lt == 230 {
				baseLayer = gopacket.DecodeFunc(decodeIEEE802154)
			} else if lt == 274 && len(data) > 8 {
				// LINKTYPE_ETHERNET_MPACKET (FPP): strip 8-byte Ethernet preamble+SFD
				data = data[8:]
				baseLayer = layers.LayerTypeEthernet
			} else if layerType := linkTypeToLayerType(lt); layerType != 0 {
				baseLayer = layerType
			} else {
				baseLayer = gopacket.DecodeFunc(func(_ []byte, _ gopacket.PacketBuilder) error {
					return unsupportedLink("unsupported capture link type %d (%s)", lt, dltDescriptions[int(lt)])
				})
			}
		}
	}

	// when not using lazy here, the packet will be decoded on the main thread!
	opts := c.config.DecodeOptions
	if len(data) == 0 {
		// Lazy decoding skips empty slices entirely, hiding even link-header errors.
		opts.Lazy = false
		baseLayer = gopacket.DecodeFunc(func(_ []byte, _ gopacket.PacketBuilder) error {
			return badLink("empty captured packet has no link header")
		})
	}
	if opts == (gopacket.DecodeOptions{}) {
		opts.NoCopy = true
	}
	p := gopacket.NewPacket(data, baseLayer, opts)
	p.Metadata().CaptureInfo = *ci

	return p
}

// linkTypeToLayerType converts a pcap link type to a gopacket layer type.
// Returns 0 if the link type is not recognized.
func linkTypeToLayerType(lt layers.LinkType) gopacket.LayerType {
	switch lt {
	case 258: // LINKTYPE_PKTAP is portable; DLT 149 is USER2 outside Darwin.
		return layers.LayerTypePktap
	case 149:
		if runtime.GOOS == "darwin" {
			return layers.LayerTypePktap
		}
		return gopacket.LayerTypePayload
	case layers.LinkTypeEthernet:
		return layers.LayerTypeEthernet
	case layers.LinkTypeRaw:
		return layerRawIP
	case layers.LinkTypeIPv4:
		return layers.LayerTypeIPv4
	case layers.LinkTypeIPv6:
		return layers.LayerTypeIPv6
	case layers.LinkTypeNull:
		return layers.LayerTypeLoopback
	case layers.LinkTypeFDDI:
		return layers.LayerTypeFDDI
	case layers.LinkTypeIEEE802_11:
		return layers.LayerTypeDot11
	case layers.LinkTypeIEEE80211Radio:
		return layers.LayerTypeRadioTap
	case layers.LinkTypePPP:
		return layers.LayerTypePPP
	case layers.LinkTypeLinuxSLL:
		return layers.LayerTypeLinuxSLL
	case layers.LinkTypeLinuxSLL2:
		return layers.LayerTypeLinuxSLL2
	case layers.LinkTypeC_HDLC:
		return layerCHDLC
	case 195, 230:
		return layerIEEE802154
	case 239:
		return layerNFLOG
	case 274: // LINKTYPE_ETHERNET_MPACKET (FPP - Frame Preemption Protocol)
		// FPP frames in pcapng are standard Ethernet frames
		return layers.LayerTypeEthernet
	default:
		return 0
	}
}

// printProgressLive prints live statistics.
func (c *Collector) printProgressLive() {
	current := atomic.LoadInt64(&c.current)
	if current%1000 == 0 {
		c.clearLine()
		if !c.config.DecoderConfig.Quiet {
			fmt.Print("running since ", time.Since(c.start), ", captured ", current, " packets...")
		}
	}
}

// dumpProto prints a protobuf Message.
//
//goland:noinspection GoUnusedFunction
func dumpProto(pb proto.Message) {
	println(proto.MarshalTextString(pb))
}

func (c *Collector) clearLine() {
	if !c.config.DecoderConfig.Quiet {
		print("\033[2K\r")
	}
}

func share(current, total int64) string {
	percent := (float64(current) / float64(total)) * 100
	var pad string
	switch {
	case percent < 10.00:
		pad = "  "
	case percent < 100.00:
		pad = " "
	}

	return pad + strconv.FormatFloat(percent, 'f', 3, 64) + "%"
}

// compileBPFToRaw compiles a BPF filter expression into raw instructions
// suitable for use with raw socket handles that require bpf.RawInstruction slices.
// This is necessary because pcapgo.EthernetHandle uses SetBPF() with raw instructions
// rather than SetBPFFilter() with a filter string like pcap.Handle does.
func compileBPFToRaw(filterExpr string) ([]bpf.RawInstruction, error) {
	compiled, err := pcap.CompileBPFFilter(layers.LinkTypeEthernet, 65535, filterExpr)
	if err != nil {
		return nil, fmt.Errorf("failed to compile BPF filter: %w", err)
	}

	instructions := make([]bpf.RawInstruction, 0, len(compiled))
	for _, instr := range compiled {
		instructions = append(instructions, bpf.RawInstruction{
			Op: instr.Code,
			Jt: instr.Jt,
			Jf: instr.Jf,
			K:  instr.K,
		})
	}

	return instructions, nil
}

func (c *Collector) printlnStdOut(args ...any) {
	if c.config.DecoderConfig.Quiet {
		_, _ = fmt.Fprintln(c.netcapLogFile, args...)
	} else {
		_, _ = fmt.Fprintln(c.netcapLogFile, args...)
		_, _ = fmt.Fprintln(os.Stdout, args...)
	}
}

func (c *Collector) printStdOut(args ...any) {
	if c.config.DecoderConfig.Quiet {
		_, _ = fmt.Fprint(c.netcapLogFile, args...)
	} else {
		_, _ = fmt.Fprint(os.Stdout, args...)
	}
}
