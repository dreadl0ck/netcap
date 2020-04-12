/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) 2017 Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

package encoder

import (
	"github.com/dreadl0ck/gopacket"
	"github.com/dreadl0ck/gopacket/layers"
	"github.com/dreadl0ck/netcap/types"
	"github.com/golang/protobuf/proto"
)

var dnsEncoder = CreateLayerEncoder(types.Type_NC_DNS, layers.LayerTypeDNS, func(layer gopacket.Layer, timestamp string) proto.Message {
	if dns, ok := layer.(*layers.DNS); ok {
		var questions []*types.DNSQuestion
		for _, q := range dns.Questions {
			questions = append(questions, &types.DNSQuestion{
				Class: int32(q.Class),
				Name:  q.Name,
				Type:  int32(q.Type),
			})
		}
		newNetResourceRecord := func(a layers.DNSResourceRecord) *types.DNSResourceRecord {
			return &types.DNSResourceRecord{
				Name:       []byte(a.Name),
				Type:       int32(a.Type),
				Class:      int32(a.Class),
				TTL:        uint32(a.TTL),
				DataLength: int32(a.DataLength),
				Data:       []byte(a.Data),
				IP:         a.IP.String(),
				NS:         []byte(a.NS),
				CNAME:      []byte(a.CNAME),
				PTR:        []byte(a.PTR),
				SOA: &types.DNSSOA{
					MName:   []byte(a.SOA.MName),
					RName:   []byte(a.SOA.RName),
					Serial:  uint32(a.SOA.Serial),
					Refresh: uint32(a.SOA.Refresh),
					Retry:   uint32(a.SOA.Retry),
					Expire:  uint32(a.SOA.Expire),
					Minimum: uint32(a.SOA.Minimum),
				},
				SRV: &types.DNSSRV{
					Priority: int32(a.SRV.Priority),
					Weight:   int32(a.SRV.Weight),
					Port:     int32(a.SRV.Port),
					Name:     []byte(a.SRV.Name),
				},
				MX: &types.DNSMX{
					Preference: int32(a.MX.Preference),
					Name:       []byte(a.MX.Name),
				},
				TXTs: a.TXTs,
			}
		}
		var answers []*types.DNSResourceRecord
		for _, a := range dns.Answers {
			answers = append(answers, newNetResourceRecord(a))
		}
		var auths []*types.DNSResourceRecord
		for _, a := range dns.Authorities {
			auths = append(auths, newNetResourceRecord(a))
		}

		var adds []*types.DNSResourceRecord
		for _, a := range dns.Additionals {
			adds = append(adds, newNetResourceRecord(a))
		}

		return &types.DNS{
			Timestamp:    timestamp,
			ID:           int32(dns.ID),
			QR:           bool(dns.QR),
			OpCode:       int32(dns.OpCode),
			AA:           bool(dns.AA),
			TC:           bool(dns.TC),
			RD:           bool(dns.RD),
			RA:           bool(dns.RA),
			Z:            int32(dns.Z),
			ResponseCode: int32(dns.ResponseCode),
			QDCount:      int32(dns.QDCount),
			ANCount:      int32(dns.ANCount),
			NSCount:      int32(dns.NSCount),
			ARCount:      int32(dns.ARCount),
			// Entries
			Questions:   questions,
			Answers:     answers,
			Authorities: auths,
			Additionals: adds,
		}
	}
	return nil
})
