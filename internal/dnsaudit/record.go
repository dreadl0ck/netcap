/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package dnsaudit

import (
	"bytes"
	"math"
	"sort"
	"strings"

	"github.com/gopacket/gopacket/layers"

	"github.com/dreadl0ck/netcap/internal/utils"
	"github.com/dreadl0ck/netcap/types"
)

// dnsResponseCodeNames maps DNS response codes to human-readable names
var dnsResponseCodeNames = map[layers.DNSResponseCode]string{
	layers.DNSResponseCodeNoErr:    "NOERROR",
	layers.DNSResponseCodeFormErr:  "FORMERR",
	layers.DNSResponseCodeServFail: "SERVFAIL",
	layers.DNSResponseCodeNXDomain: "NXDOMAIN",
	layers.DNSResponseCodeNotImp:   "NOTIMP",
	layers.DNSResponseCodeRefused:  "REFUSED",
	layers.DNSResponseCodeYXDomain: "YXDOMAIN",
	layers.DNSResponseCodeYXRRSet:  "YXRRSET",
	layers.DNSResponseCodeNXRRSet:  "NXRRSET",
	layers.DNSResponseCodeNotAuth:  "NOTAUTH",
	layers.DNSResponseCodeNotZone:  "NOTZONE",
}

// dnsQueryNameEntropy calculates Shannon entropy of a DNS query name
func QueryNameEntropy(name string) float64 {
	if len(name) == 0 {
		return 0
	}
	freq := make(map[byte]float64)
	for _, c := range []byte(name) {
		freq[c]++
	}

	// Summing in map order would vary the floating point rounding per run.
	runes := make([]byte, 0, len(freq))
	for c := range freq {
		runes = append(runes, c)
	}
	sort.Slice(runes, func(i, j int) bool { return runes[i] < runes[j] })

	var ent float64
	length := float64(len(name))
	for _, c := range runes {
		p := freq[c] / length
		if p > 0 {
			ent -= p * math.Log2(p)
		}
	}
	return ent
}

// extractTLD extracts the top-level domain from a DNS name
func TLD(name string) string {
	name = strings.TrimSuffix(name, ".")
	parts := strings.Split(name, ".")
	if len(parts) >= 1 {
		return parts[len(parts)-1]
	}
	return ""
}

// countSubdomains counts the number of subdomain levels
func SubdomainCount(name string) int {
	name = strings.TrimSuffix(name, ".")
	parts := strings.Split(name, ".")
	// Subtract 2 for domain + TLD
	if len(parts) > 2 {
		return len(parts) - 2
	}
	return 0
}

func Record(dns *layers.DNS, timestamp int64, calculateEntropy bool) *types.DNS {
	if dns != nil {
		questions := make([]*types.DNSQuestion, 0, len(dns.Questions))
		for _, q := range dns.Questions {
			questions = append(questions, &types.DNSQuestion{
				Class:   int32(q.Class),
				Name:    utils.PrintableBytes(q.Name),
				NameRaw: bytes.Clone(q.Name),
				Type:    int32(q.Type),
			})
		}
		newNetResourceRecord := func(a layers.DNSResourceRecord) *types.DNSResourceRecord {
			text := make([]string, 0, len(a.TXTs))
			for _, segment := range a.TXTs {
				text = append(text, utils.PrintableBytes(segment))
			}
			ip := ""
			if len(a.IP) != 0 {
				ip = a.IP.String()
			}
			return &types.DNSResourceRecord{
				Name:       utils.PrintableBytes(a.Name),
				NameRaw:    bytes.Clone(a.Name),
				TXTStrings: text,
				Type:       int32(a.Type),
				Class:      int32(a.Class),
				TTL:        a.TTL,
				DataLength: int32(a.DataLength),
				Data:       a.Data,
				IP:         ip,
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
					Name:       utils.PrintableBytes(a.MX.Name),
					NameRaw:    bytes.Clone(a.MX.Name),
				},
				TXTs: a.TXTs,
				SVCB: dnsSVCB(a),
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
			subdomainCount = int32(SubdomainCount(firstName))
			if calculateEntropy {
				queryNameEntropy = QueryNameEntropy(firstName)
			}
			queryNameTLD = TLD(firstName)
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

		// Calculate total DNS packet size (for amplification detection)
		packetSize := int32(len(dns.Contents))

		return &types.DNS{
			ParseStatus:  "valid",
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
			PacketSize:       packetSize,
			QueryNameTLD:     queryNameTLD,
			IsNXDOMAIN:       dns.ResponseCode == layers.DNSResponseCodeNXDomain,
			ResponseCodeName: responseCodeName,
			HasEDNS:          hasEDNS,
			EDNSPayloadSize:  ednsPayloadSize,
		}
	}

	return nil
}
