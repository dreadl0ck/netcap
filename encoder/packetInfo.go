package encoder

import "github.com/dreadl0ck/gopacket"

type packetInfo struct {
	p         gopacket.Packet
	timestamp string
	srcMAC    string
	dstMAC    string
	srcIP     string
	dstIP     string
}

func newPacketInfo(p gopacket.Packet) *packetInfo {

	i := new(packetInfo)

	i.timestamp = p.Metadata().Timestamp.UTC().String()
	i.p = p
	if ll := p.LinkLayer(); ll != nil {
		i.srcMAC = ll.LinkFlow().Src().String()
		i.dstMAC = ll.LinkFlow().Dst().String()
	}
	if nl := p.NetworkLayer(); nl != nil {
		i.srcIP = nl.NetworkFlow().Src().String()
		i.dstIP = nl.NetworkFlow().Dst().String()
	}

	return i
}
