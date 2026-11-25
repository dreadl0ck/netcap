package evidencelink

import (
	"net/netip"
	"slices"
	"time"

	"github.com/dreadl0ck/netcap/internal/dnsaudit"
	"github.com/dreadl0ck/netcap/types"
)

type findingDNSKey struct {
	scope          string
	client, server netip.Addr
}

type findingAnswer struct {
	ref   ContextRef
	chain []string
	ttl   int64
}

func (i *FindingContext) addFindingDNS(d *types.DNS, ref ContextRef) {
	if d.Timestamp <= 0 || !d.QR || d.TC || d.ResponseCode != 0 || d.ParseError != "" ||
		d.TransactionStatus != dnsaudit.DNSStatusAnswered || d.SrcPort != 53 || len(d.Questions) != 1 || len(d.Answers) > 64 {
		return
	}
	q := d.Questions[0]
	if q == nil || q.Class != 1 || q.Type != 1 && q.Type != 28 {
		return
	}
	name := contextName(q.Name)
	if name == "" {
		return
	}
	key, _, client := contextFlow(d.CommunityID, d.SrcIP, d.DstIP, d.SrcPort, d.DstPort)
	conn := i.connectionAt(key, d.Timestamp, "UDP")
	if conn == nil {
		conn = i.connectionAt(key, d.Timestamp, "TCP")
		if conn == nil {
			return
		}
	}
	chain, ttl := answerChain(name, d.Answers)
	if len(chain) == 0 {
		return
	}
	owner := chain[len(chain)-1]
	charge := 512
	for _, alias := range chain {
		charge += 16 + len(alias)
	}
	for _, rr := range d.Answers {
		if rr == nil || rr.Class != 1 || rr.Type != q.Type || rr.TTL == 0 || contextName(rr.Name) != owner {
			continue
		}
		if addr := contextAddress(rr.IP); addr.IsValid() && addr.Is4() == (rr.Type == 1) {
			addContext(i.dns, findingDNSKey{conn.scope, client, addr}, findingAnswer{ref, chain, int64(min(ttl, rr.TTL)) * int64(time.Second)})
			i.bytes += charge
		}
	}
}

// Follow only a single bounded CNAME chain from the actual question.
func answerChain(name string, records []*types.DNSResourceRecord) ([]string, uint32) {
	owner, ttl := name, uint32(300)
	chain := []string{name}
	for range 9 {
		var alias *types.DNSResourceRecord
		for _, rr := range records {
			if rr != nil && rr.Class == 1 && rr.Type == 5 && contextName(rr.Name) == owner {
				if alias != nil || rr.TTL == 0 {
					return nil, 0
				}
				alias = rr
			}
		}
		if alias == nil {
			return chain, ttl
		}
		target := alias.CNAMEText
		if target == "" {
			target = string(alias.CNAME)
		}
		owner = contextName(target)
		if owner == "" || slices.Contains(chain, owner) {
			return nil, 0
		}
		chain = append(chain, owner)
		ttl = min(ttl, alias.TTL)
	}
	return nil, 0
}

func (i *FindingContext) addDNSLink(links []RelatedEvidence, key findingFlow, at int64, client, server netip.Addr, knownName string) []RelatedEvidence {
	conn := i.connectionAt(key, at, "TCP")
	if conn == nil {
		return links
	}
	answers := i.dns[findingDNSKey{conn.scope, client, server}]
	var match *findingAnswer
	for n := range answers {
		candidate := &answers[n]
		if candidate.ref.Timestamp > conn.first || conn.first-candidate.ref.Timestamp >= candidate.ttl {
			continue
		}
		if match != nil && match.chain[0] != candidate.chain[0] {
			return links
		}
		if match == nil || candidate.ref.Timestamp > match.ref.Timestamp {
			match = candidate
		}
	}
	if match == nil {
		return links
	}
	_, authority := contextAuthority(knownName, "")
	if authority == match.chain[0] {
		return links // already named in direct evidence (or by the linked TLS hello)
	}
	relationship := "dns-same-address"
	if slices.Contains(match.chain[1:], authority) {
		relationship = "dns-resolution"
	}
	return append(links, RelatedEvidence{Relationship: relationship, Name: match.chain[0], IP: server.String(), Record: match.ref})
}
