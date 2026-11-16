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
		case 24, 25, 26, 30, 32:
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
	if next == nil {
		f.Qualifications = append(f.Qualifications, "dissector-not-implemented")
	}
	return finishBusFrame(data, offset, f, p, next)
}
