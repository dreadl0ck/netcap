package behavior

import (
	"testing"
	"time"
)

func TestInventoryLabelsAndPrefixCorrectionsPersist(t *testing.T) {
	e, sink := testEngine(t, 100)
	prefix := Fact{Scope: testFact().Scope, Kind: "prefix", Value: "192.0.2.0/24", Provenance: "configured"}
	device := Fact{Scope: prefix.Scope, Kind: "device", MAC: "00:11:22:33:44:55"}
	learn(t, e, prefix, device)
	if err := e.EditInventory(InventoryEdit{ID: factID(device), Name: "Office gateway", Role: "router", Notes: "fixture", Reason: "reviewed inventory", Version: 1}); err != nil {
		t.Fatal(err)
	}
	if err := e.EditInventory(InventoryEdit{ID: factID(prefix), Prefix: "192.0.2.128/25", Reason: "correct mask", Version: 2}); err != nil {
		t.Fatal(err)
	}
	if e.isInternal(prefix.Scope, "192.0.2.1") || !e.isInternal(prefix.Scope, "192.0.2.130") {
		t.Fatal("correction left original prefix active")
	}
	if err := e.EditInventory(InventoryEdit{ID: factID(device), Name: "stale", Reason: "stale edit", Version: 1}); err == nil {
		t.Fatal("stale inventory mutation accepted")
	}
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
	restarted, err := Open(e.config, sink)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	state := restarted.Snapshot()
	if state.Labels[factID(device)].Name != "Office gateway" || state.Corrections[factID(prefix)].Value != "192.0.2.128/25" || state.Version != 3 {
		t.Fatal("inventory metadata lost across restart")
	}
	if len(state.Observed) != 3 || len(state.Decisions) != 3 {
		t.Fatal("correction discarded original evidence/history")
	}
}

func TestLearnedDHCPLeaseDistinguishesAddressReassignment(t *testing.T) {
	e, sink := testEngine(t, 100)
	old := Fact{Scope: testFact().Scope, Kind: "binding", SrcIP: "192.0.2.10", DstIP: "192.0.2.1", MAC: "00:11:22:33:44:55", Provenance: "dhcp", LeaseSeconds: 3600}
	learn(t, e, old)
	fresh := old
	fresh.MAC = "00:11:22:33:44:66"
	if err := e.Observe(testTime.Add(2*time.Second), fresh); err != nil {
		t.Fatal(err)
	}
	arp := fresh
	arp.DstIP, arp.Provenance, arp.LeaseSeconds = "", "arp", 0
	if err := e.Observe(testTime.Add(3*time.Second), arp); err != nil {
		t.Fatal(err)
	}
	if detectorCount(sink, "baseline.arp-conflict") != 0 || detectorCount(sink, "baseline.dhcp-reassignment") != 1 {
		t.Fatal("lease-supported address change became spoof indicator")
	}
	spoof := arp
	spoof.MAC = old.MAC
	if err := e.Observe(testTime.Add(4*time.Second), spoof); err != nil {
		t.Fatal(err)
	}
	if detectorCount(sink, "baseline.arp-conflict") != 1 {
		t.Fatal("old approved MAC bypassed current lease conflict")
	}
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
	restarted, err := Open(e.config, sink)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	if !restarted.leaseMatches(testTime.Add(5*time.Second).UnixNano(), arp) {
		t.Fatal("restart lost current DHCP lease")
	}
}

func TestUnknownDHCPServerDoesNotSuppressConflict(t *testing.T) {
	e, sink := testEngine(t, 100)
	old := Fact{Scope: testFact().Scope, Kind: "binding", SrcIP: "192.0.2.10", MAC: "00:11:22:33:44:55", Provenance: "arp"}
	learn(t, e, old)
	rogue := old
	rogue.MAC, rogue.DstIP, rogue.Provenance, rogue.LeaseSeconds = "00:11:22:33:44:66", "192.0.2.99", "dhcp", 3600
	if err := e.Observe(testTime.Add(2*time.Second), rogue); err != nil {
		t.Fatal(err)
	}
	rogue.Provenance, rogue.DstIP, rogue.LeaseSeconds = "arp", "", 0
	if err := e.Observe(testTime.Add(10*time.Minute), rogue); err != nil {
		t.Fatal(err)
	}
	if detectorCount(sink, "baseline.arp-conflict") != 1 {
		t.Fatal("unknown DHCP server disabled conflict detection")
	}
}
