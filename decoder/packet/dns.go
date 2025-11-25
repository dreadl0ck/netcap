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
	"math"
	"strings"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gogo/protobuf/proto"

	"github.com/dreadl0ck/netcap/types"
)

// dnsResponseCodeNames maps DNS response codes to human-readable names
var dnsResponseCodeNames = map[layers.DNSResponseCode]string{
	layers.DNSResponseCodeNoErr:     "NOERROR",
	layers.DNSResponseCodeFormErr:   "FORMERR",
	layers.DNSResponseCodeServFail:  "SERVFAIL",
	layers.DNSResponseCodeNXDomain:  "NXDOMAIN",
	layers.DNSResponseCodeNotImp:    "NOTIMP",
	layers.DNSResponseCodeRefused:   "REFUSED",
	layers.DNSResponseCodeYXDomain:  "YXDOMAIN",
	layers.DNSResponseCodeYXRRSet:   "YXRRSET",
	layers.DNSResponseCodeNXRRSet:   "NXRRSET",
	layers.DNSResponseCodeNotAuth:   "NOTAUTH",
	layers.DNSResponseCodeNotZone:   "NOTZONE",
}

// dnsQueryNameEntropy calculates Shannon entropy of a DNS query name
func dnsQueryNameEntropy(name string) float64 {
	if len(name) == 0 {
		return 0
	}
	freq := make(map[rune]float64)
	for _, c := range name {
		freq[c]++
	}
	var ent float64
	length := float64(len(name))
	for _, count := range freq {
		p := count / length
		if p > 0 {
			ent -= p * math.Log2(p)
		}
	}
	return ent
}

// extractTLD extracts the top-level domain from a DNS name
func extractTLD(name string) string {
	name = strings.TrimSuffix(name, ".")
	parts := strings.Split(name, ".")
	if len(parts) >= 1 {
		return parts[len(parts)-1]
	}
	return ""
}

// countSubdomains counts the number of subdomain levels
func countSubdomains(name string) int {
	name = strings.TrimSuffix(name, ".")
	parts := strings.Split(name, ".")
	// Subtract 2 for domain + TLD
	if len(parts) > 2 {
		return len(parts) - 2
	}
	return 0
}

var dnsDecoder = newGoPacketDecoder(
	types.Type_NC_DNS,
	layers.LayerTypeDNS,
	"The Domain Name System is a hierarchical and decentralized naming system for computers, services, or other resources connected to the Internet or a private network",
	func(layer gopacket.Layer, timestamp int64) proto.Message {
		if dns, ok := layer.(*layers.DNS); ok {
			questions := make([]*types.DNSQuestion, 0, len(dns.Questions))
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
			answers := make([]*types.DNSResourceRecord, 0, len(dns.Answers))
			for _, a := range dns.Answers {
				answers = append(answers, newNetResourceRecord(a))
			}
			auths := make([]*types.DNSResourceRecord, 0, len(dns.Authorities))
			for _, a := range dns.Authorities {
				auths = append(auths, newNetResourceRecord(a))
			}

			adds := make([]*types.DNSResourceRecord, 0, len(dns.Additionals))
			for _, a := range dns.Additionals {
				adds = append(adds, newNetResourceRecord(a))
			}

			// Security monitoring fields
			var (
				queryNameLength  int32
				subdomainCount   int32
				queryNameEntropy float64
				queryNameTLD     string
			)
			if len(dns.Questions) > 0 {
				firstName := string(dns.Questions[0].Name)
				queryNameLength = int32(len(firstName))
				subdomainCount = int32(countSubdomains(firstName))
				if conf.CalculateEntropy {
					queryNameEntropy = dnsQueryNameEntropy(firstName)
				}
				queryNameTLD = extractTLD(firstName)
			}

			// Check for EDNS0 OPT record
			var hasEDNS bool
			var ednsPayloadSize int32
			for _, add := range dns.Additionals {
				if add.Type == layers.DNSTypeOPT {
					hasEDNS = true
					ednsPayloadSize = int32(add.Class) // Class field contains UDP payload size for OPT
					break
				}
			}

			responseCodeName := dnsResponseCodeNames[dns.ResponseCode]
			if responseCodeName == "" {
				responseCodeName = "UNKNOWN"
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
				// Security monitoring fields
				QueryNameLength:  queryNameLength,
				SubdomainCount:   subdomainCount,
				QueryNameEntropy: queryNameEntropy,
				QueryNameTLD:     queryNameTLD,
				IsNXDOMAIN:       dns.ResponseCode == layers.DNSResponseCodeNXDomain,
				ResponseCodeName: responseCodeName,
				HasEDNS:          hasEDNS,
				EDNSPayloadSize:  ednsPayloadSize,
			}
		}

		return nil
	},
)
