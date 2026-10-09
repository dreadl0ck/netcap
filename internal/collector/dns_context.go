package collector

import (
	"github.com/dreadl0ck/netcap/internal/dnsaudit"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"strconv"
)

func (c *Collector) observeDNSContext(packet gopacket.Packet) {
	if c.dnsContext == nil {
		return
	}
	ci := &packet.Metadata().CaptureInfo
	scope := strconv.Itoa(ci.InterfaceIndex)
	for _, layer := range packet.Layers() {
		if vlan, ok := layer.(*layers.Dot1Q); ok {
			scope += "/" + strconv.Itoa(int(vlan.VLANIdentifier))
		}
	}
	network := packet.NetworkLayer()
	if network == nil {
		return
	}
	source, destination := network.NetworkFlow().Src().String(), network.NetworkFlow().Dst().String()
	if udp, ok := packet.TransportLayer().(*layers.UDP); ok && (udp.SrcPort == 53 || udp.DstPort == 53) {
		if layer := packet.Layer(layers.LayerTypeDNS); layer != nil {
			if dns, ok := layer.(*layers.DNS); ok {
				record := dnsaudit.Record(dns, ci.Timestamp.UnixNano(), false)
				record.SrcIP, record.DstIP = source, destination
				record.SrcPort, record.DstPort = int32(udp.SrcPort), int32(udp.DstPort)
				c.dnsContext.Observe(record, scope)
			}
		}
	}
	stamp := c.dnsContext.Lookup(scope, source, destination, ci.Timestamp.UnixNano())
	ci.AncillaryData = append(append([]any{}, ci.AncillaryData...), stamp)
}
