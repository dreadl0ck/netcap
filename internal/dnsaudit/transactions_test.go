package dnsaudit

import (
	"fmt"
	"math"
	"testing"

	"github.com/dreadl0ck/netcap/types"
)

func dnsMsg(at int64, qr bool, id int32, name string) *types.DNS {
	d := &types.DNS{Timestamp: at, QR: qr, ID: id, Questions: []*types.DNSQuestion{{Name: name, Type: 1, Class: 1}},
		SrcIP: "192.0.2.10", DstIP: "192.0.2.53", SrcPort: 40000, DstPort: 53}
	if qr {
		d.SrcIP, d.DstIP, d.SrcPort, d.DstPort = d.DstIP, d.SrcIP, d.DstPort, d.SrcPort
	}
	return d
}

func TestDNSTransactionPairing(t *testing.T) {
	tx := newDNSTransactions()
	q := dnsMsg(1_000, false, 7, "Example.COM.")
	tx.observe(q)
	if q.TransactionStatus != DNSStatusQuery || q.QueryTransmissions != 1 || q.RTT != 0 {
		t.Fatalf("query: %+v", q)
	}
	retry := dnsMsg(2_000, false, 7, "example.com")
	tx.observe(retry)
	if retry.TransactionStatus != DNSStatusRetransmission || retry.QueryTransmissions != 2 {
		t.Fatalf("retransmission: %+v", retry)
	}
	r := dnsMsg(2_500, true, 7, "example.com")
	tx.observe(r)
	// RTT is measured from the latest transmission, not the first.
	if r.TransactionStatus != DNSStatusAnswered || r.RTT != 500 || r.QueryTransmissions != 2 {
		t.Fatalf("answer: %+v", r)
	}
	dup := dnsMsg(2_600, true, 7, "example.com")
	tx.observe(dup)
	if dup.TransactionStatus != DNSStatusUnsolicited || dup.RTT != 0 {
		t.Fatalf("duplicate response must not pair twice: %+v", dup)
	}
	if pending, _ := tx.stats(); pending != 0 {
		t.Fatalf("pending = %d", pending)
	}
}

func TestDNSTransactionKeyIsolation(t *testing.T) {
	tx := newDNSTransactions()
	tx.observe(dnsMsg(1, false, 7, "a.example"))
	// Same ID, different question: a spoofed or unrelated response.
	other := dnsMsg(2, true, 7, "b.example")
	tx.observe(other)
	if other.TransactionStatus != DNSStatusUnsolicited {
		t.Fatalf("question mismatch paired: %+v", other)
	}
	// Same ID and question from a different client port.
	wrongPort := dnsMsg(3, true, 7, "a.example")
	wrongPort.DstPort = 40001
	tx.observe(wrongPort)
	if wrongPort.TransactionStatus != DNSStatusUnsolicited {
		t.Fatalf("port mismatch paired: %+v", wrongPort)
	}
	// Records without endpoints or questions are left untouched.
	bare := &types.DNS{ID: 1}
	tx.observe(bare)
	if bare.TransactionStatus != "" {
		t.Fatalf("unkeyed record annotated: %+v", bare)
	}
}

func TestDNSTransactionTimeoutAndReorder(t *testing.T) {
	tx := newDNSTransactions()
	tx.observe(dnsMsg(0, false, 9, "slow.example"))
	late := dnsMsg(DNSTransactionTimeout+1, true, 9, "slow.example")
	tx.observe(late)
	if late.TransactionStatus != DNSStatusLate || late.RTT != DNSTransactionTimeout+1 {
		t.Fatalf("late: %+v", late)
	}
	tx.observe(dnsMsg(100, false, 10, "x.example"))
	backwards := dnsMsg(50, true, 10, "x.example")
	tx.observe(backwards)
	if backwards.TransactionStatus != DNSStatusReordered || backwards.RTT != 0 {
		t.Fatalf("reordered timestamps must not produce a negative RTT: %+v", backwards)
	}
	tx.observe(dnsMsg(0, false, 11, "re.example"))
	fresh := dnsMsg(DNSTransactionTimeout+10, false, 11, "re.example")
	tx.observe(fresh)
	if fresh.TransactionStatus != DNSStatusQuery || fresh.QueryTransmissions != 1 {
		t.Fatalf("query after timeout must start a new transaction: %+v", fresh)
	}
}

func TestDNSTransactionCapacity(t *testing.T) {
	tx := newDNSTransactions()
	for i := 0; i < dnsMaxPending+5; i++ {
		tx.observe(dnsMsg(int64(i), false, 1, fmt.Sprintf("h%d.example", i)))
	}
	pending, evicted := tx.stats()
	if pending != dnsMaxPending || evicted != 5 {
		t.Fatalf("pending=%d evicted=%d", pending, evicted)
	}
	first := dnsMsg(1_000_000, true, 1, "h0.example")
	tx.observe(first)
	if first.TransactionStatus != DNSStatusUnsolicited {
		t.Fatalf("evicted query paired: %+v", first)
	}
}

func TestProducerConsumerRatio(t *testing.T) {
	for _, c := range []struct {
		produced, consumed int64
		want               float64
	}{{0, 0, 0}, {100, 0, 1}, {0, 100, -1}, {300, 100, 0.5}, {-1, 5, 0}, {math.MaxInt64, math.MaxInt64, 0}, {math.MaxInt64, 0, 1}} {
		if got := ProducerConsumerRatio(c.produced, c.consumed); got != c.want {
			t.Fatalf("PCR(%d,%d)=%v want %v", c.produced, c.consumed, got, c.want)
		}
	}
}

func TestDNSCaptureScopeAndClassIsolation(t *testing.T) {
	tx := newDNSTransactions()
	tx.observeScoped(dnsMsg(1, false, 1, "a.example"), "interface-1/vlan-10")
	wrong := dnsMsg(2, true, 1, "a.example")
	tx.observeScoped(wrong, "interface-1/vlan-11")
	if wrong.TransactionStatus != DNSStatusUnsolicited {
		t.Fatal("paired across VLANs")
	}
	wrong = dnsMsg(3, true, 1, "a.example")
	wrong.Questions[0].Class = 3
	tx.observeScoped(wrong, "interface-1/vlan-10")
	if wrong.TransactionStatus != DNSStatusUnsolicited {
		t.Fatal("paired across DNS classes")
	}
	correct := dnsMsg(4, true, 1, "a.example")
	tx.observeScoped(correct, "interface-1/vlan-10")
	if correct.TransactionStatus != DNSStatusAnswered {
		t.Fatal("lost original scoped query")
	}
}
