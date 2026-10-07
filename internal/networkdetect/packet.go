package networkdetect

import (
	"fmt"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

func PacketEvents(packet gopacket.Packet, scope Scope) []Event {
	if packet == nil || packet.NetworkLayer() == nil {
		return nil
	}
	scope.VLANs = nil
	if index := packet.Metadata().CaptureInfo.InterfaceIndex; index > 0 {
		scope.Interface = fmt.Sprintf("%s#%d", scope.Interface, index)
	}
	for _, layer := range packet.Layers() {
		if vlan, ok := layer.(*layers.Dot1Q); ok {
			scope.VLANs = append(scope.VLANs, vlan.VLANIdentifier)
		}
	}
	if len(scope.VLANs) > 4 {
		return nil
	}
	net := packet.NetworkLayer().NetworkFlow()
	base := Event{At: packet.Metadata().CaptureInfo.Timestamp.UnixNano(), Scope: scope, SrcIP: net.Src().String(), DstIP: net.Dst().String()}
	var events []Event
	if layer := packet.Layer(layers.LayerTypeDNS); layer != nil {
		dns := layer.(*layers.DNS)
		if !dns.QR {
			for n, q := range dns.Questions {
				if n >= 32 {
					break
				}
				if len(q.Name) > 253 {
					continue
				}
				ev := base
				ev.Kind = "dns"
				ev.Name = string(q.Name)
				ev.QType = uint16(q.Type)
				events = append(events, ev)
			}
		}
	}
	if layer := packet.Layer(layers.LayerTypeTCP); layer != nil {
		tcp := layer.(*layers.TCP)
		base.SrcPort = uint16(tcp.SrcPort)
		base.DstPort = uint16(tcp.DstPort)
		base.Seq = tcp.Seq
		if tcp.SYN && !tcp.ACK && !tcp.RST {
			ev := base
			ev.Kind = "syn"
			events = append(events, ev)
		}
		if len(tcp.Payload) > 0 {
			ev := base
			ev.Kind = "data"
			ev.Payload = tcp.Payload
			if tcp.SYN {
				ev.Seq++
			}
			events = append(events, ev)
		}
		if tcp.FIN || tcp.RST {
			ev := base
			ev.Kind = "end"
			events = append(events, ev)
		}
	}
	if layer := packet.Layer(layers.LayerTypeICMPv4); layer != nil {
		icmp := layer.(*layers.ICMPv4)
		if icmp.TypeCode.Type() == layers.ICMPv4TypeEchoRequest {
			ev := base
			ev.Kind = "icmp"
			ev.Seq = uint32(icmp.Id)<<16 | uint32(icmp.Seq)
			ev.Payload = icmp.Payload
			events = append(events, ev)
		}
	}
	if layer := packet.Layer(layers.LayerTypeICMPv6); layer != nil {
		icmp := layer.(*layers.ICMPv6)
		if icmp.TypeCode.Type() == layers.ICMPv6TypeEchoRequest {
			if echo := packet.Layer(layers.LayerTypeICMPv6Echo); echo != nil {
				header := echo.(*layers.ICMPv6Echo)
				ev := base
				ev.Kind = "icmp"
				ev.Seq = uint32(header.Identifier)<<16 | uint32(header.SeqNumber)
				ev.Payload = header.Payload
				events = append(events, ev)
			}
		}
	}
	return events
}
