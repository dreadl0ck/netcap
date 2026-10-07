package flow

import (
	"context"
	"errors"
	"math"
	"net/url"
	"testing"

	"github.com/dreadl0ck/netcap/types"
	"github.com/gogo/protobuf/proto"
)

func flowFixture(id, src, dst string, bytes, seconds int64, sequence uint64) *types.Connection {
	return &types.Connection{ObservationID: id, CounterSemantics: "tuple-cumulative", SnapshotSequence: sequence,
		SrcIP: src, DstIP: dst, SrcPort: "12345", DstPort: "80", NetworkProto: "IPv4", TransportProto: "TCP",
		TimestampFirst: 0, TimestampLast: seconds * 1e9, TotalSize64: bytes, NumPackets64: bytes / 1000}
}

func TestFlowQueryReconcilesSnapshotsAndRanksExactCounters(t *testing.T) {
	d := NewDataset(10)
	records := []*types.Connection{
		flowFixture("a", "10.0.0.1", "192.0.2.1", 600000000, 60, 2),
		flowFixture("a", "10.0.0.1", "192.0.2.1", 100000000, 10, 1),
		flowFixture("b", "10.0.0.2", "192.0.2.1", 3000000000, 90, 1),
		flowFixture("c", "10.0.0.1", "192.0.2.2", 100000000, 10, 1),
	}
	for i, c := range records {
		if err := d.Add(c, uint64(i)); err != nil {
			t.Fatal(err)
		}
	}
	q := Query{StartNs: 0, EndNs: 60e9, GroupBy: "srcIP", SortBy: "bytes", Limit: 100}
	r, err := d.Query(context.Background(), q)
	if err != nil {
		t.Fatal(err)
	}
	if r.ReadRecords != 4 || r.CollapsedSnapshots != 1 || r.Matched != 3 || r.TotalGroups != 2 || r.Groups[0].Key != "10.0.0.2" || r.Groups[0].Bytes != 3000000000 {
		t.Fatalf("incorrect rankings: %+v", r)
	}
	a := r.Groups[1]
	if a.Bytes != 700000000 || a.Observations != 2 || a.DistinctPeers != 2 || a.AverageBitsPerSecond != 80000000 || a.Members[0].Ordinal != 0 {
		t.Fatalf("snapshot double count/rate error: %+v", a)
	}
	q.Expression = `InSubnet(SrcIP, "10.0.0.0/24") && ParsePort(DstPort) == 80 && !(SrcIP == "10.0.0.2") && TotalSize64 >= 100000000`
	r, err = d.Query(context.Background(), q)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Groups) != 1 || r.Groups[0].Bytes != 700000000 || len(r.Limitations) == 0 {
		t.Fatalf("filter or scope semantics: %+v", r)
	}
	q.StartNs, q.EndNs = 60e9+1, 90e9
	r, err = d.Query(context.Background(), q)
	if err != nil {
		t.Fatal(err)
	}
	if r.Matched != 0 {
		t.Fatalf("out-of-window observations matched: %+v", r)
	}
}

func TestFlowSnapshotValidation(t *testing.T) {
	base := flowFixture("a", "10.0.0.1", "192.0.2.1", 100, 10, 1)
	for _, tc := range []struct {
		name   string
		change func(*types.Connection)
	}{
		{"conflict", func(c *types.Connection) { c.TotalSize64++ }},
		{"tuple-reuse", func(c *types.Connection) { c.DstIP = "192.0.2.2" }},
		{"decreasing-count", func(c *types.Connection) { c.SnapshotSequence = 2; c.TotalSize64-- }},
		{"shrinking-window", func(c *types.Connection) { c.SnapshotSequence = 2; c.TimestampFirst = 1 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := NewDataset(10)
			if err := d.Add(base, 0); err != nil {
				t.Fatal(err)
			}
			c := proto.Clone(base).(*types.Connection)
			tc.change(c)
			if err := d.Add(c, 1); err == nil {
				t.Fatal("accepted ambiguous/conflicting evidence")
			}
		})
	}
	d := NewDataset(10)
	legacy := proto.Clone(base).(*types.Connection)
	legacy.CounterSemantics = ""
	legacy.ObservationID = ""
	legacy.SnapshotSequence = 0
	if err := d.Add(legacy, 0); err != nil {
		t.Fatal(err)
	}
	if err := d.Add(legacy, 1); !errors.Is(err, ErrAmbiguousLegacy) {
		t.Fatalf("legacy duplicates: %v", err)
	}
	d = NewDataset(10)
	if err := d.Add(base, 0); err != nil {
		t.Fatal(err)
	}
	if err := d.Add(legacy, 1); !errors.Is(err, ErrAmbiguousLegacy) {
		t.Fatalf("mixed evidence: %v", err)
	}
}

func TestFlowQueryBoundsIPv6AndOverflow(t *testing.T) {
	q, err := ParseQuery(url.Values{"startNs": {"1"}, "endNs": {"2"}, "filter": {`InSubnet(SrcIP, "2001:db8::/32")`}})
	if err != nil {
		t.Fatal(err)
	}
	d := NewDataset(1)
	c := flowFixture("v6", "2001:db8::1", "2001:db8::2", 600000000, 60, 1)
	c.NetworkProto = "IPv6"
	if err := d.Add(c, 0); err != nil {
		t.Fatal(err)
	}
	r, err := d.Query(context.Background(), q)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Groups) != 1 || r.Groups[0].AverageBitsPerSecond != 80000000 {
		t.Fatalf("IPv6/rate: %+v", r)
	}
	if err := d.Add(flowFixture("b", "10.0.0.1", "192.0.2.1", 1, 1, 1), 1); err == nil {
		t.Fatal("ignored observation budget")
	}
	if _, err := ParseQuery(url.Values{"startNs": {"0"}, "endNs": {"1"}, "filter": {"true", "false"}}); err == nil {
		t.Fatal("silently broadened duplicate query")
	}
	d = NewDataset(10)
	for i, id := range []string{"a", "b"} {
		if err := d.Add(flowFixture(id, "10.0.0.1", []string{"192.0.2.1", "192.0.2.2"}[i], math.MaxInt64, 1, 1), uint64(i)); err != nil {
			t.Fatal(err)
		}
	}
	q.Expression = ""
	if _, err := d.Query(context.Background(), q); err == nil {
		t.Fatal("overflowed aggregate accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := NewDataset(1).Query(ctx, q); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled empty query: %v", err)
	}
}
