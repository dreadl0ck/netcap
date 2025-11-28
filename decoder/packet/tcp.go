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

package packet

import (
	"encoding/binary"
	"strconv"
	"strings"

	"github.com/gogo/protobuf/proto"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	"github.com/dreadl0ck/netcap/types"
)

// TCP option types
const (
	tcpOptMSS         = 2
	tcpOptWindowScale = 3
	tcpOptSACK        = 4
	tcpOptTimestamp   = 8
)

var tcpDecoder = newGoPacketDecoder(
	types.Type_NC_TCP,
	layers.LayerTypeTCP,
	"The Transmission Control Protocol (TCP) is a connection-oriented communications protocol, that facilitates the exchange of messages between computing devices in a network",
	func(layer gopacket.Layer, timestamp int64) proto.Message {
		if tcp, ok := layer.(*layers.TCP); ok {
			var (
				opts    []*types.TCPOption
				payload []byte
			)
			if conf.IncludePayloads {
				payload = layer.LayerPayload()
			}
			var e float64
			if conf.CalculateEntropy {
				e = entropy(tcp.Payload)
			}

			// Security monitoring fields
			var (
				optFingerprint strings.Builder
				mss            int32
				windowScale    int32
				hasSACK        bool
				tsVal          uint32
				tsEcr          uint32
			)

			for i, o := range tcp.Options {
				opts = append(opts, &types.TCPOption{
					OptionData:   o.OptionData,
					OptionLength: int32(o.OptionLength),
					OptionType:   int32(o.OptionType),
				})

				// Build options fingerprint
				if i > 0 {
					optFingerprint.WriteString(",")
				}
				optFingerprint.WriteString(strconv.Itoa(int(o.OptionType)))

				// Extract security-relevant option values
				switch o.OptionType {
				case tcpOptMSS:
					if len(o.OptionData) >= 2 {
						mss = int32(binary.BigEndian.Uint16(o.OptionData))
					}
				case tcpOptWindowScale:
					if len(o.OptionData) >= 1 {
						windowScale = int32(o.OptionData[0])
					}
				case tcpOptSACK:
					hasSACK = true
				case tcpOptTimestamp:
					if len(o.OptionData) >= 8 {
						tsVal = binary.BigEndian.Uint32(o.OptionData[:4])
						tsEcr = binary.BigEndian.Uint32(o.OptionData[4:8])
					}
				}
			}

			// Build flags string
			var flags []string
			if tcp.FIN {
				flags = append(flags, "FIN")
			}
			if tcp.SYN {
				flags = append(flags, "SYN")
			}
			if tcp.RST {
				flags = append(flags, "RST")
			}
			if tcp.PSH {
				flags = append(flags, "PSH")
			}
			if tcp.ACK {
				flags = append(flags, "ACK")
			}
			if tcp.URG {
				flags = append(flags, "URG")
			}
			if tcp.ECE {
				flags = append(flags, "ECE")
			}
			if tcp.CWR {
				flags = append(flags, "CWR")
			}
			if tcp.NS {
				flags = append(flags, "NS")
			}

			return &types.TCP{
				Timestamp:          timestamp,
				SrcPort:            int32(tcp.SrcPort),
				DstPort:            int32(tcp.DstPort),
				SeqNum:             tcp.Seq,
				AckNum:             tcp.Ack,
				DataOffset:         int32(tcp.DataOffset),
				FIN:                tcp.FIN,
				SYN:                tcp.SYN,
				RST:                tcp.RST,
				PSH:                tcp.PSH,
				ACK:                tcp.ACK,
				URG:                tcp.URG,
				ECE:                tcp.ECE,
				CWR:                tcp.CWR,
				NS:                 tcp.NS,
				Window:             int32(tcp.Window),
				Checksum:           int32(tcp.Checksum),
				Urgent:             int32(tcp.Urgent),
				Padding:            tcp.Padding,
				Options:            opts,
				PayloadEntropy:     e,
				PayloadSize:        int32(len(tcp.Payload)),
				Payload:            payload,
				OptionsFingerprint: optFingerprint.String(),
				MSS:                mss,
				WindowScale:        windowScale,
				HasSACK:            hasSACK,
				TSval:              tsVal,
				TSecr:              tsEcr,
				IsRSTWithData:      tcp.RST && len(tcp.Payload) > 0,
				IsSYNWithData:      tcp.SYN && len(tcp.Payload) > 0,
				FlagsStr:           strings.Join(flags, ","),
			}
		}

		return nil
	},
)
