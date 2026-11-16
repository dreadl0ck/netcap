package collector

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"strconv"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

func decodeUpperPDU(data []byte, p gopacket.PacketBuilder) error {
	f := busFrame(252, "Wireshark Upper PDU")
	offset, count := 0, 0
	protocol, selector := "", uint16(0)
	var tableValue *uint32
	valuePending := false
	for {
		if len(data)-offset < 4 || count >= 1024 {
			return badLink("Upper PDU TLV framing exceeds packet or limit")
		}
		kind, size := binary.BigEndian.Uint16(data[offset:]), int(binary.BigEndian.Uint16(data[offset+2:]))
		offset += 4
		if size > len(data)-offset {
			return badLink("Upper PDU option exceeds packet")
		}
		value := data[offset : offset+size]
		offset += size
		pending := valuePending
		valuePending = false
		if kind == 0 {
			if size != 0 {
				return badLink("Upper PDU end marker has data")
			}
			break
		}
		f.Fields[fmt.Sprintf("tag_%d_%d", count, kind)] = hex.EncodeToString(value)
		count++
		switch kind {
		case 12, 13, 14:
			name := bytes.TrimRight(value, "\x00")
			if len(name) == 0 {
				return badLink("Upper PDU protocol selector is empty")
			}
			for _, c := range name {
				if c < 33 || c > 126 {
					return badLink("Upper PDU dissector name is not ASCII")
				}
			}
			if protocol == "" {
				protocol, selector = string(name), kind
				valuePending = kind == 14
			}
		case 20, 21, 22, 23:
			length := 4
			if kind >= 22 {
				length = 16
			}
			if size != length {
				return badLink("Upper PDU address option has invalid length")
			}
			if kind == 20 || kind == 22 {
				if f.Source == "" {
					f.Source = net.IP(value).String()
				}
			} else if f.Destination == "" {
				f.Destination = net.IP(value).String()
			}
		case 32:
			if size != 4 {
				return badLink("Upper PDU table value has invalid length")
			}
			if pending && selector == 14 {
				number := binary.BigEndian.Uint32(value)
				tableValue = &number
			} else {
				f.Qualifications = append(f.Qualifications, "unselected-or-nonadjacent-table-value")
			}
			f.Fields["table_value"] = strconv.FormatUint(uint64(binary.BigEndian.Uint32(value)), 10)
		case 24, 25, 26, 30:
			if size != 4 {
				return badLink("Upper PDU integer option has invalid length")
			}
			f.Fields[fmt.Sprintf("value_%d", kind)] = strconv.FormatUint(uint64(binary.BigEndian.Uint32(value)), 10)
		}
	}
	if protocol == "" {
		return badLink("Upper PDU has no protocol selector")
	}
	f.Fields["dissector"], f.Fields["selector_tag"] = protocol, strconv.Itoa(int(selector))
	f.Qualifications = append(f.Qualifications, "exported-PDU-metadata-not-original-link-headers")
	var next gopacket.Decoder
	if selector == 12 {
		known := map[string]gopacket.LayerType{"ip": layers.LayerTypeIPv4, "ipv6": layers.LayerTypeIPv6, "eth": layers.LayerTypeEthernet, "arp": layers.LayerTypeARP, "tcp": layers.LayerTypeTCP, "udp": layers.LayerTypeUDP, "sctp": layers.LayerTypeSCTP, "icmp": layers.LayerTypeICMPv4, "icmpv6": layers.LayerTypeICMPv6, "dns": layers.LayerTypeDNS, "igmp": layers.LayerTypeIGMP, "llc": layers.LayerTypeLLC}
		if decoder, ok := known[protocol]; ok {
			next, f.PayloadProtocol = decoder, protocol
		}
	}
	if selector == 14 && tableValue != nil {
		switch protocol {
		case "ethertype":
			next = map[uint32]gopacket.LayerType{0x0800: layers.LayerTypeIPv4, 0x86dd: layers.LayerTypeIPv6, 0x0806: layers.LayerTypeARP, 0x8100: layers.LayerTypeDot1Q, 0x8847: layers.LayerTypeMPLS, 0x88cc: layers.LayerTypeLinkLayerDiscovery}[*tableValue]
		case "ip.proto", "ipv6.nxt":
			next = map[uint32]gopacket.LayerType{1: layers.LayerTypeICMPv4, 2: layers.LayerTypeIGMP, 6: layers.LayerTypeTCP, 17: layers.LayerTypeUDP, 41: layers.LayerTypeIPv6, 47: layers.LayerTypeGRE, 50: layers.LayerTypeIPSecESP, 51: layers.LayerTypeIPSecAH, 58: layers.LayerTypeICMPv6, 132: layers.LayerTypeSCTP}[*tableValue]
		case "udp.port":
			next = map[uint32]gopacket.LayerType{53: layers.LayerTypeDNS, 5353: layers.LayerTypeDNS, 123: layers.LayerTypeNTP, 67: layers.LayerTypeDHCPv4, 68: layers.LayerTypeDHCPv4}[*tableValue]
		}
		if layer, ok := next.(gopacket.LayerType); ok && layer == gopacket.LayerTypeZero {
			next = nil
		}
		if next != nil {
			f.PayloadProtocol = protocol + ":" + strconv.FormatUint(uint64(*tableValue), 10)
		}
	}
	if selector == 13 && protocol == "dns_udp" && len(data)-offset >= 12 {
		body := data[offset:]
		questions := int(binary.BigEndian.Uint16(body[4:6]))
		answers := int(binary.BigEndian.Uint16(body[6:8])) + int(binary.BigEndian.Uint16(body[8:10])) + int(binary.BigEndian.Uint16(body[10:12]))
		if (questions > 0 || answers > 0) && questions+answers <= 256 && body[3]&0x40 == 0 {
			next = layers.LayerTypeDNS
			f.PayloadProtocol = "dns"
		}
	}
	if next == nil {
		f.Qualifications = append(f.Qualifications, "dissector-not-implemented")
	}
	return finishBusFrame(data, offset, f, p, next)
}
