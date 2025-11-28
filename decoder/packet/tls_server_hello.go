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

	"github.com/dreadl0ck/ja3"
	"github.com/dreadl0ck/tlsx"
	"github.com/gogo/protobuf/proto"
	"github.com/gopacket/gopacket"

	"github.com/dreadl0ck/netcap/types"
)

var tlsServerHelloDecoder = newPacketDecoder(
	types.Type_NC_TLSServerHello,
	"TLSServerHello",
	"The server hello from a Transport Layer Security handshake",
	nil,
	func(p gopacket.Packet) proto.Message {
		hello := tlsx.GetServerHello(p)
		if hello != nil {

			extensions := make([]int32, len(hello.Extensions))
			for i, v := range hello.Extensions {
				extensions[i] = int32(v)
			}

			var (
				srcPort, dstPort int
				srcMac, dstMac   string
				srcIP, dstIP     string
			)

			if ll := p.LinkLayer(); ll != nil {
				if len(ll.LinkFlow().Src().Raw()) > 0 {
					srcMac = ll.LinkFlow().Src().String()
				}
				if len(ll.LinkFlow().Dst().Raw()) > 0 {
					dstMac = ll.LinkFlow().Dst().String()
				}
			}

			if nl := p.NetworkLayer(); nl != nil {
				if len(nl.NetworkFlow().Src().Raw()) > 0 {
					srcIP = p.NetworkLayer().NetworkFlow().Src().String()
				}
				if len(nl.NetworkFlow().Dst().Raw()) > 0 {
					dstIP = p.NetworkLayer().NetworkFlow().Dst().String()
				}
			}

			if tl := p.TransportLayer(); tl != nil {
				if len(tl.TransportFlow().Src().Raw()) >= 2 {
					srcPort = int(binary.BigEndian.Uint16(p.TransportLayer().TransportFlow().Src().Raw()))
				}
				if len(tl.TransportFlow().Dst().Raw()) >= 2 {
					dstPort = int(binary.BigEndian.Uint16(p.TransportLayer().TransportFlow().Dst().Raw()))
				}
			}

			return &types.TLSServerHello{
				Timestamp:                    p.Metadata().Timestamp.UnixNano(),
				Version:                      int32(hello.Vers),
				Random:                       hello.Random,
				SessionID:                    hello.SessionID,
				CipherSuite:                  int32(hello.CipherSuite),
				CompressionMethod:            int32(hello.CompressionMethod),
				NextProtoNeg:                 hello.NextProtoNeg,
				NextProtos:                   hello.NextProtos,
				OCSPStapling:                 hello.OCSPStapling,
				TicketSupported:              hello.TicketSupported,
				SecureRenegotiationSupported: hello.SecureRenegotiationSupported,
				SecureRenegotiation:          hello.SecureRenegotiation,
				AlpnProtocol:                 hello.AlpnProtocol,
				Ems:                          hello.Ems,
				Scts:                         hello.Scts,
				SupportedVersion:             int32(hello.SupportedVersion),
				SelectedIdentityPresent:      hello.SelectedIdentityPresent,
				SelectedIdentity:             int32(hello.SelectedIdentity),
				Cookie:                       hello.Cookie,
				SelectedGroup:                int32(hello.SelectedGroup),
				Ja3S:                         ja3.DigestHexJa3s(&hello.ServerHelloBasic),
				SrcIP:                        srcIP,
				DstIP:                        dstIP,
				SrcMAC:                       srcMac,
				DstMAC:                       dstMac,
				SrcPort:                      int32(srcPort),
				DstPort:                      int32(dstPort),
				Extensions:                   extensions,
			}
		}

		return nil
	},
	nil,
)
