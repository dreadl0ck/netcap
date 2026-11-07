package networkdetect

import (
	"fmt"
	"testing"
)

func TestBrowsingIsNotScan(t *testing.T) {
	e, _ := New(DefaultConfig())
	for i := 0; i < 100; i++ {
		ev := baseEvent("syn", i)
		ev.DstIP = fmt.Sprintf("198.51.100.%d", i+1)
		ev.DstPort = []uint16{80, 443}[i%2]
		alerts, err := e.Observe(ev)
		if err != nil {
			t.Fatal(err)
		}
		for _, a := range alerts {
			if a.RuleName == "network.scan" {
				t.Fatal("browsing flagged", a)
			}
		}
	}
	for _, a := range e.Flush() {
		if a.RuleName == "network.scan" {
			t.Fatal("browsing flagged at EOF", a)
		}
	}
}

func TestScanAggregation(t *testing.T) {
	for _, kind := range []string{"syn", "refused"} {
		e, _ := New(DefaultConfig())
		count := 0
		for i := 0; i < 100; i++ {
			ev := baseEvent(kind, i)
			ev.DstIP = fmt.Sprintf("198.51.100.%d", i+1)
			ev.DstPort = 22
			if kind == "refused" {
				ev.DstPort = 443
			}
			alerts, err := e.Observe(ev)
			if err != nil {
				t.Fatal(err)
			}
			for _, a := range alerts {
				if a.RuleName == "network.scan" {
					count++
				}
			}
		}
		for _, a := range e.Flush() {
			if a.RuleName == "network.scan" {
				count++
				if a.Count != 91 {
					t.Fatalf("lost repeated matches: %d", a.Count)
				}
			}
		}
		if count != 1 {
			t.Fatalf("%s: %d scan alerts, want 1", kind, count)
		}
	}
}
