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
	"fmt"
	"sync"

	"github.com/gogo/protobuf/proto"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	"github.com/dreadl0ck/netcap/types"
)

// NetFlow v9 field type names (common ones)
var netflowV9FieldNames = map[uint16]string{
	1:  "IN_BYTES",
	2:  "IN_PKTS",
	4:  "PROTOCOL",
	5:  "SRC_TOS",
	6:  "TCP_FLAGS",
	7:  "L4_SRC_PORT",
	8:  "IPV4_SRC_ADDR",
	10: "INPUT_SNMP",
	11: "L4_DST_PORT",
	12: "IPV4_DST_ADDR",
	13: "OUTPUT_SNMP",
	14: "IPV4_NEXT_HOP",
	15: "SRC_AS",
	16: "DST_AS",
	21: "LAST_SWITCHED",
	22: "FIRST_SWITCHED",
	27: "IPV6_SRC_ADDR",
	28: "IPV6_DST_ADDR",
	56: "IN_SRC_MAC",
	57: "OUT_DST_MAC",
	61: "DIRECTION",
}

// templateField represents a field definition from a template record
type templateField struct {
	Type   uint16
	Length uint16
}

// NetFlow v9 template cache
var (
	netflowTemplates sync.Map // map[uint32]map[uint16][]templateField  (sourceID -> templateID -> fields)
)

var netflowDecoder = newPacketDecoder(
	types.Type_NC_NetFlowV9,
	"NetFlowV9",
	"NetFlow v9 provides IP flow information for network monitoring and analysis",
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

		// NetFlow v9 common ports
		if udp.DstPort != 2055 && udp.DstPort != 9995 && udp.DstPort != 9996 &&
			udp.SrcPort != 2055 && udp.SrcPort != 9995 && udp.SrcPort != 9996 {
			return nil
		}

		payload := udp.Payload
		if len(payload) < 20 {
			return nil
		}

		// NetFlow v9 header
		version := binary.BigEndian.Uint16(payload[0:2])
		if version != 9 {
			return nil
		}

		count := binary.BigEndian.Uint16(payload[2:4])
		sysUptime := binary.BigEndian.Uint32(payload[4:8])
		unixSecs := binary.BigEndian.Uint32(payload[8:12])
		seqNum := binary.BigEndian.Uint32(payload[12:16])
		sourceID := binary.BigEndian.Uint32(payload[16:20])

		var flowSets []*types.NetFlowV9FlowSet
		isTemplate := false
		offset := 20

		for offset+4 <= len(payload) {
			fsID := binary.BigEndian.Uint16(payload[offset : offset+2])
			fsLen := int(binary.BigEndian.Uint16(payload[offset+2 : offset+4]))

			if fsLen < 4 || offset+fsLen > len(payload) {
				break
			}

			var fields []*types.NetFlowV9Field

			if fsID == 0 {
				// Template FlowSet
				isTemplate = true
				fields = parseNetflowTemplateFlowSet(payload[offset+4:offset+fsLen], sourceID)
			} else if fsID == 1 {
				// Options Template FlowSet
				isTemplate = true
			} else if fsID >= 256 {
				// Data FlowSet - decode using cached template
				fields = parseNetflowDataFlowSet(payload[offset+4:offset+fsLen], fsID, sourceID)
			}

			flowSets = append(flowSets, &types.NetFlowV9FlowSet{
				FlowSetID: int32(fsID),
				Length:    int32(fsLen),
				Fields:   fields,
			})

			offset += fsLen
		}

		var srcIP, dstIP string
		if nl := p.NetworkLayer(); nl != nil {
			srcIP = nl.NetworkFlow().Src().String()
			dstIP = nl.NetworkFlow().Dst().String()
		}

		return &types.NetFlowV9{
			Timestamp:      p.Metadata().Timestamp.UnixNano(),
			Version:        int32(version),
			Count:          int32(count),
			SysUptime:      int64(sysUptime),
			UnixSecs:       int64(unixSecs),
			SequenceNumber: int32(seqNum),
			SourceID:       int32(sourceID),
			IsTemplate:     isTemplate,
			FlowSets:       flowSets,
			SrcIP:          srcIP,
			DstIP:          dstIP,
		}
	},
	nil,
)

// parseNetflowTemplateFlowSet parses template records and caches them
func parseNetflowTemplateFlowSet(data []byte, sourceID uint32) []*types.NetFlowV9Field {
	var fields []*types.NetFlowV9Field
	offset := 0

	for offset+4 <= len(data) {
		templateID := binary.BigEndian.Uint16(data[offset : offset+2])
		fieldCount := binary.BigEndian.Uint16(data[offset+2 : offset+4])
		offset += 4

		var tmplFields []templateField
		for i := 0; i < int(fieldCount) && offset+4 <= len(data); i++ {
			fType := binary.BigEndian.Uint16(data[offset : offset+2])
			fLen := binary.BigEndian.Uint16(data[offset+2 : offset+4])
			offset += 4

			tmplFields = append(tmplFields, templateField{Type: fType, Length: fLen})

			name := netflowV9FieldNames[fType]
			if name == "" {
				name = fmt.Sprintf("Field_%d", fType)
			}

			fields = append(fields, &types.NetFlowV9Field{
				Type:     int32(fType),
				TypeName: name,
			})
		}

		// Cache the template
		templatesI, _ := netflowTemplates.LoadOrStore(sourceID, &sync.Map{})
		templates := templatesI.(*sync.Map)
		templates.Store(templateID, tmplFields)
	}

	return fields
}

// parseNetflowDataFlowSet decodes data records using cached templates
func parseNetflowDataFlowSet(data []byte, templateID uint16, sourceID uint32) []*types.NetFlowV9Field {
	templatesI, ok := netflowTemplates.Load(sourceID)
	if !ok {
		return nil
	}

	templates := templatesI.(*sync.Map)
	tmplI, ok := templates.Load(templateID)
	if !ok {
		return nil
	}

	tmplFields, ok := tmplI.([]templateField)
	if !ok {
		return nil
	}

	// Calculate record size from template
	recordSize := 0
	for _, tf := range tmplFields {
		recordSize += int(tf.Length)
	}
	if recordSize == 0 {
		return nil
	}

	var fields []*types.NetFlowV9Field
	offset := 0

	// Decode all records in the flowset
	for offset+recordSize <= len(data) {
		for _, tf := range tmplFields {
			if offset+int(tf.Length) > len(data) {
				return fields
			}

			value := data[offset : offset+int(tf.Length)]
			offset += int(tf.Length)

			name := netflowV9FieldNames[tf.Type]
			if name == "" {
				name = fmt.Sprintf("Field_%d", tf.Type)
			}

			var decoded string
			switch tf.Type {
			case 8, 12, 14: // IPv4 addresses
				if len(value) == 4 {
					decoded = fmt.Sprintf("%d.%d.%d.%d", value[0], value[1], value[2], value[3])
				}
			case 7, 11: // Ports
				if len(value) == 2 {
					decoded = fmt.Sprintf("%d", binary.BigEndian.Uint16(value))
				}
			case 4: // Protocol
				if len(value) == 1 {
					decoded = fmt.Sprintf("%d", value[0])
				}
			case 1, 2: // Bytes/Packets
				switch len(value) {
				case 4:
					decoded = fmt.Sprintf("%d", binary.BigEndian.Uint32(value))
				case 8:
					decoded = fmt.Sprintf("%d", binary.BigEndian.Uint64(value))
				}
			}

			fields = append(fields, &types.NetFlowV9Field{
				Type:         int32(tf.Type),
				TypeName:     name,
				Value:        value,
				DecodedValue: decoded,
			})
		}
	}

	return fields
}
