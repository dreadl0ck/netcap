package webui

import (
	"compress/gzip"
	"os"
	"path/filepath"
	"testing"

	"github.com/dreadl0ck/netcap/internal/delimited"
	"github.com/dreadl0ck/netcap/types"
)

func writeDNS(t *testing.T, dir string, records []*types.DNS) {
	t.Helper()
	f, err := os.Create(filepath.Join(dir, "DNS.ncap.gz"))
	if err != nil {
		t.Fatal(err)
	}
	gz := gzip.NewWriter(f)
	w := delimited.NewWriter(gz)
	if err := w.PutProto(&types.Header{Type: types.Type_NC_DNS}); err != nil {
		t.Fatal(err)
	}
	for _, r := range records {
		if err := w.PutProto(r); err != nil {
			t.Fatal(err)
		}
	}
	gz.Close()
	f.Close()
}

func TestDomainTransactionSummary(t *testing.T) {
	dir := t.TempDir()
	q := func(name, status string, qr bool, rtt int64) *types.DNS {
		return &types.DNS{QR: qr, TransactionStatus: status, RTT: rtt, SrcIP: "10.0.0.1",
			Questions: []*types.DNSQuestion{{Name: name, Type: 1}}}
	}
	records := []*types.DNS{
		q("a.example", "query", false, 0), q("a.example", "answered", true, 10),
		q("a.example", "query", false, 0), q("a.example", "retransmission", false, 0), q("a.example", "answered", true, 30),
		q("a.example", "query", false, 0), // never answered
		q("a.example", "unsolicited", true, 0),
		q("a.example", "query", false, 0), q("a.example", "reordered", true, 0),
		q("b.example", "query", false, 0), q("b.example", "late", true, 40e9),
		q("legacy.example", "", false, 0), // written before pairing existed
	}
	// A second question in a message must not be counted as a transaction.
	multi := q("a.example", "query", false, 0)
	multi.Questions = append([]*types.DNSQuestion{{Name: "c.example"}}, multi.Questions...)
	records = append(records, multi)
	writeDNS(t, dir, records)

	domains, err := readDomains(dir)
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]DomainSummary{}
	for _, d := range domains {
		byName[d.Domain] = d
	}
	a := byName["a.example"].Transactions
	if a == nil || a.Queries != 4 || a.Retransmissions != 1 || a.Answered != 2 || a.Unsolicited != 1 || a.Unanswered != 1 || a.Reordered != 1 ||
		a.RTTSamples != 2 || a.RTTMedianNS != 10 || a.RTTP95NS != 30 {
		t.Fatalf("a.example: %+v", a)
	}
	b := byName["b.example"].Transactions
	if b == nil || b.Late != 1 || b.Unanswered != 0 || b.RTTMedianNS != 40e9 {
		t.Fatalf("b.example: %+v", b)
	}
	if byName["legacy.example"].Transactions != nil {
		t.Fatal("legacy records must not report an empty transaction summary")
	}
	if c := byName["c.example"].Transactions; c == nil || c.Queries != 1 {
		t.Fatalf("first question carries the pairing: %+v", c)
	}
}

func TestRTTBudgetIsBoundedAndVisible(t *testing.T) {
	budget := 2
	aggregate := &domainAggregator{rttBudget: &budget}
	for i := 0; i < 4; i++ {
		aggregate.observeTransaction(&types.DNS{TransactionStatus: "answered", RTT: int64(i + 1)})
	}
	summary := aggregate.transactionSummary()
	if budget != 0 || len(aggregate.rtts) != 2 || summary.Answered != 4 || !summary.RTTTruncated {
		t.Fatalf("unbounded or hidden RTT sampling: %+v", summary)
	}
}
