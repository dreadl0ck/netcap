// Package dnscontext snapshots packet-ingress DNS evidence before dispatch.
// Workers never consult mutable cross-flow state when evaluating a record.
package dnscontext

import (
	"container/list"
	"net/netip"
	"strings"

	"github.com/dreadl0ck/netcap/internal/dnsaudit"
	"github.com/dreadl0ck/netcap/types"
)

const MaxEntries = 65536
const MaxWindowNS int64 = 3600e9

type Snapshot struct {
	Name       string
	AnsweredAt int64
	State      string
}

type answer struct {
	key       string
	name      string
	at, until int64
}

type Tracker struct {
	pairing *dnsaudit.DNSTransactionTracker
	answers map[string]*list.Element
	order   *list.List
	limit   int
}

func New() *Tracker {
	return &Tracker{pairing: dnsaudit.NewPacketTracker(), answers: make(map[string]*list.Element), order: list.New(), limit: MaxEntries}
}

func key(scope, client, destination string) string {
	return scope + "\x00" + client + "\x00" + destination
}

// Observe accepts UDP DNS records in ingress order. Unsolicited, late,
// reordered and failed responses never create resolution context.
func (t *Tracker) Observe(record *types.DNS, scope string) {
	t.pairing.ObserveScoped(record, scope)
	if !record.QR || record.ResponseCode != 0 || record.TransactionStatus != dnsaudit.DNSStatusAnswered || len(record.Questions) != 1 || record.Questions[0] == nil || record.Questions[0].Class != 1 {
		return
	}
	name := strings.ToLower(strings.TrimSuffix(record.Questions[0].Name, "."))
	if name == "" || len(name) > 253 {
		return
	}
	for _, rr := range record.Answers {
		if rr == nil || (rr.Type != 1 && rr.Type != 28) || rr.Class != 1 || rr.Type != record.Questions[0].Type || strings.ToLower(strings.TrimSuffix(rr.Name, ".")) != name {
			continue
		}
		ip, err := netip.ParseAddr(rr.IP)
		if err != nil {
			continue
		}
		window := int64(rr.TTL) * 1e9
		if window > MaxWindowNS {
			window = MaxWindowNS
		}
		if record.Timestamp > (1<<63-1)-window {
			continue
		}
		k := key(scope, record.DstIP, ip.Unmap().String())
		entry := answer{key: k, name: name, at: record.Timestamp, until: record.Timestamp + window}
		if existing := t.answers[k]; existing != nil {
			existing.Value = entry
			t.order.MoveToBack(existing)
		} else {
			if len(t.answers) >= t.limit {
				oldest := t.order.Front()
				delete(t.answers, oldest.Value.(answer).key)
				t.order.Remove(oldest)
			}
			t.answers[k] = t.order.PushBack(entry)
		}
	}
}

// Lookup returns a value, not a pointer into the tracker. Its lifetime is the
// first packet's lifetime, independent of subsequent answers or eviction.
func (t *Tracker) Lookup(scope, source, destination string, at int64) Snapshot {
	missing := Snapshot{State: "unobserved"}
	entry := t.answers[key(scope, source, destination)]
	if entry == nil {
		return missing
	}
	a := entry.Value.(answer)
	if at < a.at || at > a.until {
		return missing
	}
	return Snapshot{Name: a.name, AnsweredAt: a.at, State: "resolved"}
}
