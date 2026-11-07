package networkdetect

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/dreadl0ck/netcap/types"
)

func telegram(at int64) Event {
	ev := baseEvent("dns", 0)
	ev.At, ev.Name, ev.QType = at, "api.telegram.org", 1
	return ev
}

func TestAggregationWindowsEpochZeroAndEOFFlush(t *testing.T) {
	c := DefaultConfig()
	c.DedupNS = 10e9
	e, _ := New(c)
	for i := 0; i < 10; i++ {
		if rows, err := e.Observe(telegram(int64(i) * 1e9)); err != nil || len(rows) != 0 {
			t.Fatal("premature flush", rows, err)
		}
	}
	if s := e.Stats(); s.Matches != 10 || s.Alerts != 0 || s.PendingAggregates != 1 {
		t.Fatal(s)
	}
	rows, err := e.Observe(telegram(10e9))
	if err != nil || len(rows) != 1 {
		t.Fatal("half-open window failed", rows, err)
	}
	a := rows[0]
	if a.Timestamp != 0 || a.FirstSeen != 0 || a.LastSeen != 9e9 || a.Count != 10 || len(a.Examples) != 8 || !strings.Contains(a.Notes, "flush=window") {
		t.Fatal(a)
	}
	var last struct {
		At int64 `json:"at"`
	}
	if err := json.Unmarshal([]byte(a.Examples[7]), &last); err != nil || last.At != 9e9 {
		t.Fatal("latest example lost", a.Examples, err)
	}
	if late, err := e.Observe(telegram(0)); err != nil || len(late) != 0 || e.Stats().Late != 1 {
		t.Fatal("zero not treated as late after observed watermark", late, err, e.Stats())
	}
	end := e.Flush()
	if len(end) != 1 || end[0].Count != 1 || end[0].FirstSeen != 10e9 || end[0].AggregateKey != a.AggregateKey || !strings.Contains(end[0].Notes, "flush=eof") {
		t.Fatal(end)
	}
	if len(e.Flush()) != 0 || e.Stats().PendingAggregates != 0 || e.Stats().Alerts != 2 {
		t.Fatal("non-idempotent finalization", e.Stats())
	}
}

func TestAggregationCapacityFlushPreservesCounts(t *testing.T) {
	c := DefaultConfig()
	c.MaxKeys = 2
	var events []Event
	for i := 0; i < 20; i++ {
		ev := telegram(int64(i))
		ev.Scope.Interface = string(rune('a' + i%3))
		events = append(events, ev)
	}
	e, _ := New(c)
	var all []*types.Alert
	for _, ev := range events {
		a, err := e.Observe(ev)
		if err != nil {
			t.Fatal(err)
		}
		all = append(all, a...)
		if e.Stats().PendingAggregates > 2 {
			t.Fatal("unbounded pending rows")
		}
	}
	all = append(all, e.Flush()...)
	var count uint64
	for _, a := range all {
		count += a.Count
	}
	if count != 20 || e.Stats().CapacityFlushes != 18 || e.Stats().Overflow != 0 {
		t.Fatal("capacity discarded evidence", count, e.Stats())
	}
	if !reflect.DeepEqual(all, replay(t, c, events)) {
		t.Fatal("capacity flush not deterministic")
	}
}

func TestAggregationKeysSeparateScanShapesServicesAndScope(t *testing.T) {
	c := DefaultConfig()
	c.ScanTargets = 2
	var events []Event
	for _, port := range []uint16{22, 23} {
		for _, ip := range []string{"198.51.100.1", "198.51.100.2", "198.51.100.3"} {
			ev := baseEvent("syn", 0)
			ev.At, ev.DstPort, ev.DstIP = int64(len(events)), port, ip
			events = append(events, ev)
		}
	}
	keys := map[string]bool{}
	for _, a := range replay(t, c, events) {
		if keys[a.AggregateKey] {
			t.Fatal("separate scan shapes share a key")
		}
		keys[a.AggregateKey] = true
	}
	// Two horizontal services and three vertical destinations.
	if len(keys) != 5 {
		t.Fatal(keys)
	}
	a, b := telegram(0), telegram(1)
	b.Scope.VLANs = []uint16{2}
	if rows := replay(t, c, []Event{a, b}); len(rows) != 2 || rows[0].AggregateKey == rows[1].AggregateKey {
		t.Fatal("cross-scope aggregation", rows)
	}
	c.DedupNS = 0
	if rows := replay(t, c, []Event{a, a}); len(rows) != 2 || rows[0].Count != 1 || rows[1].Count != 1 {
		t.Fatal("immediate mode lost matches", rows)
	}
}

func TestApplicationEpochZeroAndBeaconAggregation(t *testing.T) {
	c := DefaultConfig()
	e := NewApplication(c)
	o := httpObservation(0)
	o.At, o.DstPort = 0, 443
	if rows := e.Observe(o); len(rows) != 0 {
		t.Fatal(rows)
	}
	rows := e.Flush()
	if len(rows) != 1 || rows[0].FirstSeen != 0 || rows[0].Timestamp != 0 || rows[0].Count != 1 {
		t.Fatal("application epoch lost", rows)
	}
	var events []Event
	for i := 0; i < 12; i++ {
		ev := beaconSYN(int64(i)*30e9, uint32(i))
		ev.SrcPort += uint16(i)
		events = append(events, ev)
	}
	rows = replay(t, c, events)
	if len(rows) != 1 || rows[0].Count != 5 {
		t.Fatal("beacon repeats not retained", rows)
	}
	var evidence Evidence
	if err := json.Unmarshal([]byte(rows[0].MatchedRecord), &evidence); err != nil || evidence.FirstSeen != 0 {
		t.Fatal("epoch first beacon lost", evidence, err)
	}
}

func FuzzFTPActiveTarget(f *testing.F) {
	f.Add("PORT", "192,0,2,10,156,64", "192.0.2.10")
	f.Add("EPRT", "|2|2001:db8::1|40000|", "2001:db8::1")
	f.Fuzz(func(t *testing.T, op, arg, client string) {
		if len(arg) > maxFTPLine {
			return
		}
		port, ok := ftpActiveTarget(op, arg, client)
		if ok && port == 0 {
			t.Fatal("accepted zero port")
		}
	})
}
