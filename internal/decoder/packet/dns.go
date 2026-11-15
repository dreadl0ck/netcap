package packet

import (
	"bytes"
	"github.com/dreadl0ck/netcap/internal/dnsaudit"
	"github.com/dreadl0ck/netcap/types"
	"github.com/gogo/protobuf/proto"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

var dnsTx = dnsaudit.NewPacketTracker()

func init() {
	gopacket.OverrideLayerType(int(layers.LayerTypeDNS), gopacket.LayerTypeMetadata{Name: "DNS", Decoder: gopacket.DecodeFunc(func(data []byte, p gopacket.PacketBuilder) error {
		d := &layers.DNS{BaseLayer: layers.BaseLayer{Contents: data}}
		err := d.DecodeFromBytes(data, p)
		p.AddLayer(d)
		p.SetApplicationLayer(d)
		return err
	})})
	layers.RegisterUDPPortLayerType(5353, layers.LayerTypeDNS)
}

var dnsDecoder = newGoPacketDecoder(types.Type_NC_DNS, layers.LayerTypeDNS,
	"The Domain Name System maps names to network addresses", func(layer gopacket.Layer, at int64) proto.Message {
		if wire, ok := layer.(*layers.DNS); ok {
			return dnsaudit.Record(wire, at, conf.CalculateEntropy)
		}
		return nil
	})

func qualifyDNSRecord(record *types.DNS, p gopacket.Packet) {
	if failed := p.ErrorLayer(); failed != nil {
		record.ParseStatus = "partial"
		record.ParseError = failed.Error().Error()
		if wire, ok := p.Layer(layers.LayerTypeDNS).(*layers.DNS); ok {
			record.RawMessage = bytes.Clone(wire.Contents)
			if len(wire.Contents) < 12 {
				record.ParseStatus = "malformed-header"
			}
		}
	}
}

func dnsQueryNameEntropy(name string) float64            { return dnsaudit.QueryNameEntropy(name) }
func extractTLD(name string) string                      { return dnsaudit.TLD(name) }
func countSubdomains(name string) int                    { return dnsaudit.SubdomainCount(name) }
func dnsSVCB(rr layers.DNSResourceRecord) *types.DNSSVCB { return dnsaudit.SVCB(rr) }
