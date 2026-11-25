package torobserve

import (
	"regexp"
	"strconv"
	"sync"

	"github.com/dreadl0ck/netcap/types"
)

var relayName = regexp.MustCompile(`(?i)^www[.][a-z2-7]{8,20}[.](?:com|net)$`)

// These legacy certificate characteristics are supporting evidence, not Tor validation.
func Candidate(c *types.TLSCertificate) bool {
	return c.CertificateSender == "server" && c.ChainIndex == 0 && !c.IsCA && !c.IsSelfSigned &&
		c.TCPObservation == "" && c.SubjectCommonName != c.IssuerCommonName &&
		len(c.SubjectAltNames) == 0 && len(c.SubjectOrganization) == 0 && len(c.IssuerOrganization) == 0 &&
		relayName.MatchString(c.SubjectCommonName) && relayName.MatchString(c.IssuerCommonName)
}

type key struct{ scope, client, server, cp, sp string }

type Observation struct {
	At     int64
	SHA256 string
}

type Index struct {
	mu           sync.RWMutex
	certificates map[key][]Observation
	count        int
}

func (i *Index) Observe(scope string, cert *types.TLSCertificate) {
	if i == nil || cert.SrcIP == "" || cert.DstIP == "" || cert.SrcPort == 0 || cert.DstPort == 0 || !Candidate(cert) {
		return
	}
	k := key{scope, cert.DstIP, cert.SrcIP, strconv.Itoa(int(cert.DstPort)), strconv.Itoa(int(cert.SrcPort))}
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.count >= 65536 {
		return
	}
	if i.certificates == nil {
		i.certificates = make(map[key][]Observation)
	}
	i.certificates[k] = append(i.certificates[k], Observation{cert.Timestamp, cert.SHA256Fingerprint})
	i.count++
}

func (i *Index) Match(c *types.Connection) string {
	if i == nil || c.TransportProto != "TCP" {
		return ""
	}
	i.mu.RLock()
	defer i.mu.RUnlock()
	for _, k := range [...]key{
		{c.NetworkScope, c.SrcIP, c.DstIP, c.SrcPort, c.DstPort},
		{c.NetworkScope, c.DstIP, c.SrcIP, c.DstPort, c.SrcPort},
	} {
		var best Observation
		for _, o := range i.certificates[k] {
			if o.At >= c.TimestampFirst && o.At <= c.TimestampLast && (best.SHA256 == "" || o.At < best.At || o.At == best.At && o.SHA256 < best.SHA256) {
				best = o
			}
		}
		if best.SHA256 != "" {
			return best.SHA256
		}
	}
	return ""
}
