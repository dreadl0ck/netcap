/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) 2017-2020 Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

package packet

import (
	"github.com/dreadl0ck/gopacket"
	"github.com/dreadl0ck/gopacket/layers"
	"github.com/gogo/protobuf/proto"

	"github.com/dreadl0ck/netcap/types"
)

var dnsDecoder = newGoPacketDecoder(
	types.Type_NC_DNS,
	layers.LayerTypeDNS,
	"The Domain Name System is a hierarchical and decentralized naming system for computers, services, or other resources connected to the Internet or a private network",
	func(layer gopacket.Layer, timestamp int64) proto.Message {
		if dns, ok := layer.(*layers.DNS); ok {
			var questions []*types.DNSQuestion
			for _, q := range dns.Questions {
				questions = append(questions, &types.DNSQuestion{
					Class: int32(q.Class),
					Name:  string(q.Name),
					Type:  int32(q.Type),
				})
			}
			newNetResourceRecord := func(a layers.DNSResourceRecord) *types.DNSResourceRecord {
				return &types.DNSResourceRecord{
					Name:       string(a.Name),
					Type:       int32(a.Type),
					Class:      int32(a.Class),
					TTL:        a.TTL,
					DataLength: int32(a.DataLength),
					Data:       a.Data,
					IP:         a.IP.String(),
					NS:         a.NS,
					CNAME:      a.CNAME,
					PTR:        a.PTR,
					SOA: &types.DNSSOA{
						MName:   a.SOA.MName,
						RName:   a.SOA.RName,
						Serial:  a.SOA.Serial,
						Refresh: a.SOA.Refresh,
						Retry:   a.SOA.Retry,
						Expire:  a.SOA.Expire,
						Minimum: a.SOA.Minimum,
					},
					SRV: &types.DNSSRV{
						Priority: int32(a.SRV.Priority),
						Weight:   int32(a.SRV.Weight),
						Port:     int32(a.SRV.Port),
						Name:     a.SRV.Name,
					},
					MX: &types.DNSMX{
						Preference: int32(a.MX.Preference),
						Name:       string(a.MX.Name),
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
				QR:           dns.QR,
				OpCode:       int32(dns.OpCode),
				AA:           dns.AA,
				TC:           dns.TC,
				RD:           dns.RD,
				RA:           dns.RA,
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
	},
)
