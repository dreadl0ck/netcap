package networkdetect

import (
	"encoding/json"
	"math"
	"testing"
)

func beaconSYN(at int64, seq uint32) Event {
	ev := baseEvent("syn", 0)
	ev.At, ev.DstIP, ev.DstPort, ev.Seq = at, "198.51.100.30", 443, seq
	return ev
}

func beaconAlerts(t *testing.T, c Config, events []Event) (n int, evidence Evidence) {
	t.Helper()
	for _, alert := range replay(t, c, events) {
		if alert.RuleName == "c2.beacon" {
			n++
			if err := json.Unmarshal([]byte(alert.MatchedRecord), &evidence); err != nil {
				t.Fatal(err)
			}
		}
	}
	return n, evidence
}

func TestBeaconStats(t *testing.T) {
	if mean, jitter := BeaconStats([]int64{0, 10, 20, 30}); mean != 10 || jitter != 0 {
		t.Fatalf("regular: %v %v", mean, jitter)
	}
	mean, jitter := BeaconStats([]int64{0, 10, 30})
	if mean != 15 || math.Abs(jitter-1.0/3) > 1e-12 {
		t.Fatalf("irregular: %v %v", mean, jitter)
	}
	if mean, jitter := BeaconStats([]int64{5}); mean != 0 || jitter != 0 {
		t.Fatal("single sample")
	}
}

func TestBeaconRetransmissionsDoNotBreakRegularity(t *testing.T) {
	c := DefaultConfig()
	var events []Event
	start := baseEvent("syn", 0).At
	for n := 0; n < 8; n++ {
		at := start + int64(n)*30e9
		events = append(events, beaconSYN(at, uint32(n+1)), beaconSYN(at+1e9, uint32(n+1)))
	}
	count, evidence := beaconAlerts(t, c, events)
	if count != 1 || evidence.Observed != 8 || evidence.Threshold != 8 || evidence.FirstSeen != start || evidence.WindowNS != c.BeaconWindowNS {
		t.Fatalf("count=%d evidence=%+v", count, evidence)
	}
	if evidence.Samples[1] != "meanInterval=30.000s" || evidence.Samples[2] != "jitter=0.000" {
		t.Fatalf("samples: %v", evidence.Samples)
	}
}

func TestBeaconDisabledAndWindowed(t *testing.T) {
	var events []Event
	start := baseEvent("syn", 0).At
	for n := 0; n < 8; n++ {
		events = append(events, beaconSYN(start+int64(n)*30e9, uint32(n+1)))
	}
	c := DefaultConfig()
	c.BeaconSamples = 0
	if n, _ := beaconAlerts(t, c, events); n != 0 {
		t.Fatal("disabled detector alerted")
	}
	// Starts older than the window no longer count toward the samples.
	c = DefaultConfig()
	c.BeaconWindowNS = 120e9
	if n, _ := beaconAlerts(t, c, events); n != 0 {
		t.Fatal("beacon assembled across the window")
	}
}

func TestBeaconConfigValidation(t *testing.T) {
	for _, mutate := range []func(*Config){
		func(c *Config) { c.BeaconSamples = 3 },
		func(c *Config) { c.BeaconSamples = maxBeaconTimes + 1 },
		func(c *Config) { c.BeaconJitter = 0 },
		func(c *Config) { c.BeaconJitter = math.NaN() },
		func(c *Config) { c.BeaconMinIntervalNS = 1e8 },
		func(c *Config) { c.BeaconWindowNS = 1e9 },
	} {
		c := DefaultConfig()
		mutate(&c)
		if c.Validate() == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	c := DefaultConfig()
	c.BeaconSamples, c.BeaconJitter = 0, 0
	if err := c.Validate(); err != nil {
		t.Fatalf("disabled detector rejected: %v", err)
	}
}

func TestBeaconSeparatesScopeAndRepeatedSequenceOnDifferentPorts(t *testing.T) {
	c := DefaultConfig()
	start := baseEvent("syn", 0).At
	var mixed, independent []Event
	for n := 0; n < 8; n++ {
		ev := beaconSYN(start+int64(n)*30e9, 7)
		ev.SrcPort = uint16(40000 + n)
		independent = append(independent, ev)
		ev.Scope.VLANs = []uint16{uint16(n%2 + 1)}
		mixed = append(mixed, ev)
	}
	if count, _ := beaconAlerts(t, c, mixed); count != 0 {
		t.Fatal("joined different VLANs")
	}
	if count, _ := beaconAlerts(t, c, independent); count != 1 {
		t.Fatal("different source ports treated as retries")
	}
}
