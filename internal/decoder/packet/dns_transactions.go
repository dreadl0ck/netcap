/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 */

package packet

import (
	"container/list"
	"strconv"
	"strings"
	"sync"

	"github.com/dreadl0ck/netcap/types"
)

// DNS transaction status values written to DNS.TransactionStatus.
const (
	DNSStatusQuery          = "query"
	DNSStatusRetransmission = "retransmission"
	DNSStatusAnswered       = "answered"
	DNSStatusLate           = "late"
	DNSStatusUnsolicited    = "unsolicited"
)

const (
	// DNSTransactionTimeout bounds how long a query waits for its response.
	// A response matching an older query is paired as late.
	DNSTransactionTimeout int64 = 30e9
	// dnsMaxPending bounds outstanding queries; the oldest is evicted first.
	dnsMaxPending = 65536
)

type dnsPending struct {
	key   string
	at    int64 // latest transmission
	sends int32
}

// dnsTransactions pairs queries and responses by capture time. Flow-symmetric
// worker sharding keeps one flow's messages ordered on one worker, while the
// mutex makes the shared table safe across flows.
type dnsTransactions struct {
	mu      sync.Mutex
	pending map[string]*list.Element
	order   *list.List
	evicted int64
}

func newDNSTransactions() *dnsTransactions {
	return &dnsTransactions{pending: map[string]*list.Element{}, order: list.New()}
}

var dnsTx = newDNSTransactions()

// dnsKey identifies a transaction from the client's perspective. ok is false
// when endpoints or the question needed for an unambiguous key are missing.
func dnsKey(d *types.DNS) (string, bool) {
	if d.SrcIP == "" || d.DstIP == "" || len(d.Questions) == 0 {
		return "", false
	}
	client, server := endpoint(d.SrcIP, d.SrcPort), endpoint(d.DstIP, d.DstPort)
	if d.QR {
		client, server = server, client
	}
	q := d.Questions[0]
	return client + "|" + server + "|" + strconv.Itoa(int(d.ID)) + "|" + strings.ToLower(strings.TrimSuffix(q.Name, ".")) + "|" + strconv.Itoa(int(q.Type)), true
}

func endpoint(ip string, port int32) string {
	return ip + "#" + strconv.Itoa(int(port))
}

// observe annotates d with its pairing state.
func (t *dnsTransactions) observe(d *types.DNS) {
	key, ok := dnsKey(d)
	if !ok {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()

	elem, found := t.pending[key]
	if !d.QR {
		// A matching query after the timeout starts a new transaction.
		if found && d.Timestamp-elem.Value.(*dnsPending).at > DNSTransactionTimeout {
			delete(t.pending, key)
			t.order.Remove(elem)
			found = false
		}
		if found {
			p := elem.Value.(*dnsPending)
			p.sends++
			p.at = d.Timestamp
			t.order.MoveToBack(elem)
			d.TransactionStatus, d.QueryTransmissions = DNSStatusRetransmission, p.sends
			return
		}
		if len(t.pending) >= dnsMaxPending {
			oldest := t.order.Front()
			delete(t.pending, oldest.Value.(*dnsPending).key)
			t.order.Remove(oldest)
			t.evicted++
		}
		t.pending[key] = t.order.PushBack(&dnsPending{key: key, at: d.Timestamp, sends: 1})
		d.TransactionStatus, d.QueryTransmissions = DNSStatusQuery, 1
		return
	}
	if !found {
		d.TransactionStatus = DNSStatusUnsolicited
		return
	}
	p := elem.Value.(*dnsPending)
	delete(t.pending, key)
	t.order.Remove(elem)
	d.QueryTransmissions = p.sends
	// Capture timestamps can run backwards across reordered packets.
	if d.Timestamp >= p.at {
		d.RTT = d.Timestamp - p.at
	}
	d.TransactionStatus = DNSStatusAnswered
	if d.RTT > DNSTransactionTimeout {
		d.TransactionStatus = DNSStatusLate
	}
}

// stats returns outstanding queries and capacity evictions.
func (t *dnsTransactions) stats() (pending int, evicted int64) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.pending), t.evicted
}

// reset drops all state between independent capture runs.
func (t *dnsTransactions) reset() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.pending = map[string]*list.Element{}
	t.order.Init()
	t.evicted = 0
}

// ProducerConsumerRatio returns (produced - consumed) / (produced + consumed)
// for one direction's byte counts, or 0 when no bytes were observed.
func ProducerConsumerRatio(produced, consumed int64) float64 {
	if produced < 0 || consumed < 0 || produced+consumed == 0 {
		return 0
	}
	return float64(produced-consumed) / float64(produced+consumed)
}
