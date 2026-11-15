package udp

import (
	"encoding/binary"

	"github.com/dreadl0ck/netcap/internal/aggregate"
	decoderconfig "github.com/dreadl0ck/netcap/internal/decoder/config"
	"github.com/dreadl0ck/netcap/internal/decoder/core"
	"github.com/dreadl0ck/netcap/internal/packetview"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

func clientFlows(data core.DataFragments) (gopacket.Flow, gopacket.Flow) {
	first := data[0]
	network, transport := first.Network(), first.Transport()
	ports := transport.Src().Raw()
	if len(ports) != 2 {
		return network, transport
	}
	port := binary.BigEndian.Uint16(ports)
	payload := first.Raw()
	response := false
	switch port {
	case 53, 5353, 137:
		dns := &layers.DNS{}
		response = dns.DecodeFromBytes(payload, gopacket.NilDecodeFeedback) == nil && dns.QR
	case 123:
		response = len(payload) >= 48 && payload[0]&7 == 4
	case 67:
		response = len(payload) >= 240 && payload[0] == 2 && binary.BigEndian.Uint32(payload[236:240]) == 0x63825363
	}
	if response {
		return network.Reverse(), transport.Reverse()
	}
	return network, transport
}

// ICMP quotes qualify an attempted UDP destination; they never establish a service.
func (u *udpStreamPool) ObserveICMPRefusal(packet gopacket.Packet) {
	var quote []byte
	decoder := layers.LayerTypeIPv4
	if layer := packet.Layer(layers.LayerTypeICMPv4); layer != nil {
		icmp := layer.(*layers.ICMPv4)
		if icmp.TypeCode.Type() != 3 || icmp.TypeCode.Code() != 3 {
			return
		}
		quote = icmp.Payload
	} else if layer := packet.Layer(layers.LayerTypeICMPv6); layer != nil {
		icmp := layer.(*layers.ICMPv6)
		if icmp.TypeCode.Type() != 1 || icmp.TypeCode.Code() != 4 || len(icmp.Payload) < 4 {
			return
		}
		quote = icmp.Payload[4:]
		decoder = layers.LayerTypeIPv6
	} else {
		return
	}
	inner := gopacket.NewPacket(quote, decoder, gopacket.NoCopy)
	if inner.NetworkLayer() == nil {
		return
	}
	udp, ok := inner.TransportLayer().(*layers.UDP)
	if !ok {
		return
	}
	key := udp.TransportFlow().FastHash() ^ inner.NetworkLayer().NetworkFlow().FastHash() ^ packetview.ScopeHash(packet)
	if decoderconfig.Instance.AggregateStore != nil {
		_ = decoderconfig.Instance.AggregateStore.Do(func(tx *aggregate.Tx) error {
			wire, found, err := tx.Get(udpFlowKey(key))
			if err != nil || !found {
				return err
			}
			flow, err := decodeUDPFlow(wire)
			if err != nil {
				return err
			}
			flow.refused = true
			return tx.Put(udpFlowKey(key), encodeUDPFlow(flow))
		})
		return
	}
	u.Lock()
	stream := u.streams[key]
	u.Unlock()
	if stream != nil {
		stream.Lock()
		stream.refused = true
		stream.Unlock()
	}
}
