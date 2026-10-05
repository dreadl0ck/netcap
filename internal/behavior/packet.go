package behavior

import (
	"bytes"
	"encoding/binary"
	"net"
	"net/netip"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

// PacketFacts extracts early evidence without TCP stream closure or active probing.
func PacketFacts(packet gopacket.Packet, scope Scope) []Fact {
	if packet == nil {
		return nil
	}
	scope.VLANs = nil
	for _, layer := range packet.Layers() {
		if vlan, ok := layer.(*layers.Dot1Q); ok {
			scope.VLANs = append(scope.VLANs, vlan.VLANIdentifier)
		}
	}
	if len(scope.VLANs) > 4 {
		return nil
	}
	var facts []Fact
	if layer := packet.Layer(layers.LayerTypeARP); layer != nil {
		arp := layer.(*layers.ARP)
		if arp.Protocol == layers.EthernetTypeIPv4 && len(arp.SourceProtAddress) == 4 && len(arp.SourceHwAddress) == 6 && !bytes.Equal(arp.SourceProtAddress, []byte{0, 0, 0, 0}) && arp.SourceHwAddress[0]&1 == 0 {
			mac := net.HardwareAddr(arp.SourceHwAddress).String()
			facts = append(facts, Fact{Scope: scope, Kind: "device", MAC: mac},
				Fact{Scope: scope, Kind: "binding", SrcIP: net.IP(arp.SourceProtAddress).String(), MAC: mac, Provenance: "arp"})
		}
	}
	network := packet.NetworkLayer()
	if network == nil {
		return facts
	}
	src, dst := network.NetworkFlow().Src().String(), network.NetworkFlow().Dst().String()
	// An undirected edge avoids treating ordinary replies as new relationships.
	if src > dst {
		src, dst = dst, src
	}
	facts = append(facts, Fact{Scope: scope, Kind: "edge", SrcIP: src, DstIP: dst})
	src, dst = network.NetworkFlow().Src().String(), network.NetworkFlow().Dst().String()
	if ipv6, ok := network.(*layers.IPv6); ok && ipv6.HopLimit == 255 {
		if layer := packet.Layer(layers.LayerTypeICMPv6RouterAdvertisement); layer != nil {
			ra := layer.(*layers.ICMPv6RouterAdvertisement)
			addr, valid := netip.AddrFromSlice(ipv6.SrcIP)
			if valid && addr.IsLinkLocalUnicast() {
				for _, option := range ra.Options {
					if option.Type == layers.ICMPv6OptPrefixInfo && len(option.Data) == 30 && option.Data[0] <= 128 && option.Data[1]&0x80 != 0 && binary.BigEndian.Uint32(option.Data[2:6]) > 0 {
						prefix, ok := netip.AddrFromSlice(option.Data[14:30])
						if ok {
							facts = append(facts, Fact{Scope: scope, Kind: "prefix", Value: netip.PrefixFrom(prefix, int(option.Data[0])).Masked().String(), Provenance: "router-advertisement"})
						}
					}
				}
			}
		}
		if layer := packet.Layer(layers.LayerTypeICMPv6NeighborAdvertisement); layer != nil {
			na := layer.(*layers.ICMPv6NeighborAdvertisement)
			addr, valid := netip.AddrFromSlice(na.TargetAddress)
			if valid && !addr.IsUnspecified() && !addr.IsMulticast() {
				for _, option := range na.Options {
					if option.Type == layers.ICMPv6OptTargetAddress && len(option.Data) == 6 && option.Data[0]&1 == 0 {
						mac := net.HardwareAddr(option.Data).String()
						facts = append(facts, Fact{Scope: scope, Kind: "device", MAC: mac}, Fact{Scope: scope, Kind: "binding", SrcIP: addr.String(), MAC: mac, Provenance: "ndp"})
					}
				}
			}
		}
	}
	if layer := packet.Layer(layers.LayerTypeTCP); layer != nil {
		tcp := layer.(*layers.TCP)
		if tcp.SYN && !tcp.ACK && tcp.DstPort != 0 {
			facts = append(facts, Fact{Scope: scope, Kind: "service", SrcIP: src, DstIP: dst, Port: uint16(tcp.DstPort), Protocol: "tcp"})
		}
	}
	if layer := packet.Layer(layers.LayerTypeDNS); layer != nil {
		dns := layer.(*layers.DNS)
		if !dns.QR {
			protocol := "udp"
			if packet.Layer(layers.LayerTypeTCP) != nil {
				protocol = "tcp"
			}
			facts = append(facts, Fact{Scope: scope, Kind: "resolver", SrcIP: src, DstIP: dst, Port: 53, Protocol: protocol})
			for i, question := range dns.Questions {
				if i >= 32 {
					break
				}
				if len(question.Name) > 0 && len(question.Name) <= 253 {
					facts = append(facts, Fact{Scope: scope, Kind: "dns", SrcIP: src, Value: string(question.Name)})
				}
			}
		}
	}
	if layer := packet.Layer(layers.LayerTypeDHCPv4); layer != nil {
		dhcp := layer.(*layers.DHCPv4)
		// Only server ACKs provide an assigned address and authoritative subnet mask.
		ack := false
		var mask net.IPMask
		for _, option := range dhcp.Options {
			if option.Type == layers.DHCPOptMessageType && len(option.Data) == 1 && option.Data[0] == byte(layers.DHCPMsgTypeAck) {
				ack = true
			}
			if option.Type == layers.DHCPOptSubnetMask && len(option.Data) == 4 {
				mask = net.IPMask(option.Data)
			}
		}
		if ack && dhcp.YourClientIP.To4() != nil {
			if ones, bits := mask.Size(); bits == 32 {
				if addr, ok := netip.AddrFromSlice(dhcp.YourClientIP.To4()); ok {
					facts = append(facts, Fact{Scope: scope, Kind: "prefix", Value: netip.PrefixFrom(addr, ones).Masked().String(), Provenance: "dhcp"})
				}
			}
			if len(dhcp.ClientHWAddr) == 6 && dhcp.ClientHWAddr[0]&1 == 0 {
				mac := dhcp.ClientHWAddr.String()
				facts = append(facts, Fact{Scope: scope, Kind: "device", MAC: mac}, Fact{Scope: scope, Kind: "binding", SrcIP: dhcp.YourClientIP.String(), MAC: mac, Provenance: "dhcp"})
			}
		}
	}
	return facts
}
