package packet

import (
	"github.com/dreadl0ck/netcap/internal/dnsaudit"
	"github.com/dreadl0ck/netcap/types"
	"github.com/gogo/protobuf/proto"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

var dnsTx = dnsaudit.NewPacketTracker()

var dnsDecoder = newGoPacketDecoder(types.Type_NC_DNS, layers.LayerTypeDNS,
	"The Domain Name System maps names to network addresses", func(layer gopacket.Layer, at int64) proto.Message {
		if wire, ok := layer.(*layers.DNS); ok {
			return dnsaudit.Record(wire, at, conf.CalculateEntropy)
		}
		return nil
	})

func dnsQueryNameEntropy(name string) float64            { return dnsaudit.QueryNameEntropy(name) }
func extractTLD(name string) string                      { return dnsaudit.TLD(name) }
func countSubdomains(name string) int                    { return dnsaudit.SubdomainCount(name) }
func dnsSVCB(rr layers.DNSResourceRecord) *types.DNSSVCB { return dnsaudit.SVCB(rr) }
