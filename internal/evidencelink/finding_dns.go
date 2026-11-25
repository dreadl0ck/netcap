package evidencelink

import (
	"net/netip"
	"time"

	"github.com/dreadl0ck/netcap/internal/dnsaudit"
	"github.com/dreadl0ck/netcap/types"
)

type findingDNSKey struct {
	scope          string
	client, server netip.Addr
}

type findingAnswer struct {
	ref  ContextRef
	name string
	ttl  int64
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
	owner, ttl := answerOwner(name, d.Answers)
	if owner == "" {
		return
	}
	for _, rr := range d.Answers {
		if rr == nil || rr.Class != 1 || rr.Type != q.Type || rr.TTL == 0 || contextName(rr.Name) != owner {
			continue
		}
		if addr := contextAddress(rr.IP); addr.IsValid() && addr.Is4() == (rr.Type == 1) {
			addContext(i.dns, findingDNSKey{conn.scope, client, addr}, findingAnswer{ref, name, int64(min(ttl, rr.TTL)) * int64(time.Second)})
			i.bytes += 512 + len(name)
		}
	}
}

// Follow only a single bounded CNAME chain from the actual question.
func answerOwner(name string, records []*types.DNSResourceRecord) (string, uint32) {
	owner, ttl := name, uint32(300)
	seen := map[string]bool{name: true}
	for range 9 {
		var alias *types.DNSResourceRecord
		for _, rr := range records {
			if rr != nil && rr.Class == 1 && rr.Type == 5 && contextName(rr.Name) == owner {
				if alias != nil || rr.TTL == 0 {
					return "", 0
				}
				alias = rr
			}
		}
		if alias == nil {
			return owner, ttl
		}
		target := alias.CNAMEText
		if target == "" {
			target = string(alias.CNAME)
		}
		owner = contextName(target)
		if owner == "" || seen[owner] {
			return "", 0
		}
		seen[owner] = true
		ttl = min(ttl, alias.TTL)
	}
	return "", 0
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
		if match != nil && match.name != candidate.name {
			return links
		}
		if match == nil || candidate.ref.Timestamp > match.ref.Timestamp {
			match = candidate
		}
	}
	if match != nil && match.name != contextName(knownName) {
		links = append(links, RelatedEvidence{Relationship: "dns-resolution", Name: match.name, IP: server.String(), Record: match.ref})
	}
	return links
}
