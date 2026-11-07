package networkdetect

import (
	"encoding/json"
	"testing"
)

func TestEpochZeroCaptureEvent(t *testing.T) {
	e, err := New(DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	ev := baseEvent("syn", 0)
	ev.At = 0
	if _, err := e.Observe(ev); err != nil {
		t.Fatalf("Unix epoch is a valid capture timestamp: %v", err)
	}
	if e.Stats().Events != 1 || e.Stats().Late != 0 {
		t.Fatal(e.Stats())
	}
}

func TestCaptureShiftedToEpochKeepsDetectionSemantics(t *testing.T) {
	c := DefaultConfig()
	var key string
	for _, origin := range []int64{1700000000e9, 0} {
		var events []Event
		for i := 0; i < 15; i++ {
			ev := baseEvent("syn", i)
			ev.At, ev.DstPort = origin+int64(i)*1e9, uint16(1000+i)
			events = append(events, ev)
		}
		rows, stats := packetReplay(t, c, events)
		if len(rows) != 1 || stats.Events != 15 || stats.Late != 0 {
			t.Fatal(rows, stats)
		}
		a := rows[0]
		var evidence Evidence
		if err := json.Unmarshal([]byte(a.MatchedRecord), &evidence); err != nil {
			t.Fatal(err)
		}
		if a.Name != "network.scan" || a.Count != 6 || a.FirstSeen != origin+9e9 || a.LastSeen != origin+14e9 || evidence.FirstSeen != origin || evidence.Observed != 10 {
			t.Fatal("capture-time semantics changed", a, evidence)
		}
		if key != "" && key != a.AggregateKey {
			t.Fatal("timestamp changed subject identity")
		}
		key = a.AggregateKey
	}
	e, _ := New(c)
	ev := telegram(-1)
	if _, err := e.Observe(ev); err == nil || e.Stats().Events != 0 {
		t.Fatal("negative timestamp accepted")
	}
}
