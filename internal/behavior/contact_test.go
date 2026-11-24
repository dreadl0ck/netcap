package behavior

import (
	"path/filepath"
	"testing"
	"time"
)

func TestFirstPublicContactUsesApprovedScopeAndSurvivesRestart(t *testing.T) {
	policy := DefaultPolicy()
	policy.FirstPublicContact = true
	sink := &testSink{}
	cfg := Config{Path: filepath.Join(t.TempDir(), "Behavior.json"), MinLearning: time.Second, MinSamples: 2, Policy: &policy}
	e, err := Open(cfg, sink)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = e.Close() }()
	known := Fact{Scope: testFact().Scope, Kind: "service", Protocol: "tcp", Port: 443, SrcIP: "192.168.1.2", DstIP: "198.51.100.4"}
	learn(t, e, known)
	newContact := known
	newContact.Port, newContact.DstIP = 447, "198.51.100.5"
	otherPort := newContact
	otherPort.Port = 449
	knownHost := known
	knownHost.Port = 447
	otherScope := newContact
	otherScope.Scope.Interface = "en1"
	web := newContact
	web.Port, web.DstIP = 443, "198.51.100.6"
	if err := e.Observe(testTime.Add(2*time.Second), knownHost, web, otherScope, newContact, otherPort); err != nil {
		t.Fatal(err)
	}
	assertContact := func() {
		t.Helper()
		got := 0
		for _, a := range sink.alerts {
			if a.RuleName == "baseline.first-public-contact" {
				got++
				if a.DstIP != newContact.DstIP || a.SrcIP != newContact.SrcIP {
					t.Fatalf("unexpected contact: %v", a)
				}
			}
		}
		if got != 1 {
			t.Fatalf("first-contact alerts = %d, want 1", got)
		}
	}
	assertContact()
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
	e, err = Open(cfg, sink)
	if err != nil {
		t.Fatal(err)
	}
	otherPort.Port = 450
	if err := e.Observe(testTime.Add(10*time.Minute), otherPort); err != nil {
		t.Fatal(err)
	}
	assertContact()
}
