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

	"github.com/gogo/protobuf/proto"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	"github.com/dreadl0ck/netcap/types"
)

// LLMNR uses DNS wire format on UDP port 5355.
// It differs from DNS in the C (conflict) and T (tentative) flag bits.
var llmnrDecoder = newPacketDecoder(
	types.Type_NC_LLMNR,
	"LLMNR",
	"Link-Local Multicast Name Resolution allows name resolution on the local network segment without a DNS server",
	nil,
	func(p gopacket.Packet) proto.Message {
		udpLayer := p.Layer(layers.LayerTypeUDP)
		if udpLayer == nil {
			return nil
		}

		udp, ok := udpLayer.(*layers.UDP)
		if !ok {
			return nil
		}

		// LLMNR uses UDP port 5355
		if udp.DstPort != 5355 && udp.SrcPort != 5355 {
			return nil
		}

		payload := udp.Payload
		if len(payload) < 12 {
			return nil
		}

		// Parse DNS wire format header manually to extract LLMNR-specific flags
		id := binary.BigEndian.Uint16(payload[0:2])
		flags := binary.BigEndian.Uint16(payload[2:4])

		qr := flags&0x8000 != 0
		opCode := int32((flags >> 11) & 0xF)
		c := flags&0x0400 != 0  // Conflict flag (bit 10, replaces AA in DNS)
		tc := flags&0x0200 != 0 // Truncation
		t := flags&0x0080 != 0  // Tentative flag (bit 7, replaces RD in DNS)
		responseCode := int32(flags & 0xF)

		qdCount := binary.BigEndian.Uint16(payload[4:6])
		anCount := binary.BigEndian.Uint16(payload[6:8])
		nsCount := binary.BigEndian.Uint16(payload[8:10])
		arCount := binary.BigEndian.Uint16(payload[10:12])

		// Parse questions and answers using gopacket's DNS decoder
		var dns layers.DNS
		if err := dns.DecodeFromBytes(payload, gopacket.NilDecodeFeedback); err != nil {
			return nil
		}

		questions := make([]*types.DNSQuestion, 0, len(dns.Questions))
		for _, q := range dns.Questions {
			questions = append(questions, &types.DNSQuestion{
				Class: int32(q.Class),
				Name:  string(q.Name),
				Type:  int32(q.Type),
			})
		}

		newRR := func(a layers.DNSResourceRecord) *types.DNSResourceRecord {
			return &types.DNSResourceRecord{
				Name:       string(a.Name),
				Type:       int32(a.Type),
				Class:      int32(a.Class),
				TTL:        a.TTL,
				DataLength: int32(a.DataLength),
				Data:       a.Data,
				IP:         a.IP.String(),
				NS:         a.NS,
				CNAME:      a.CNAME,
				PTR:        a.PTR,
			}
		}

		answers := make([]*types.DNSResourceRecord, 0, len(dns.Answers))
		for _, a := range dns.Answers {
			answers = append(answers, newRR(a))
		}

		auths := make([]*types.DNSResourceRecord, 0, len(dns.Authorities))
		for _, a := range dns.Authorities {
			auths = append(auths, newRR(a))
		}

		adds := make([]*types.DNSResourceRecord, 0, len(dns.Additionals))
		for _, a := range dns.Additionals {
			adds = append(adds, newRR(a))
		}

		// Extract IP addresses
		var srcIP, dstIP string
		if nl := p.NetworkLayer(); nl != nil {
			srcIP = nl.NetworkFlow().Src().String()
			dstIP = nl.NetworkFlow().Dst().String()
		}

		return &types.LLMNR{
			Timestamp:    p.Metadata().Timestamp.UnixNano(),
			ID:           int32(id),
			QR:           qr,
			OpCode:       opCode,
			C:            c,
			TC:           tc,
			T:            t,
			ResponseCode: responseCode,
			QDCount:      int32(qdCount),
			ANCount:      int32(anCount),
			NSCount:      int32(nsCount),
			ARCount:      int32(arCount),
			Questions:    questions,
			Answers:      answers,
			Authorities:  auths,
			Additionals:  adds,
			SrcIP:        srcIP,
			DstIP:        dstIP,
			SrcPort:      int32(udp.SrcPort),
			DstPort:      int32(udp.DstPort),
		}
	},
	nil,
)
