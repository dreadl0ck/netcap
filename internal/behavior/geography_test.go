package behavior

import (
	"testing"
	"time"
)

func TestGeographicNoveltyAndExplicitPolicy(t *testing.T) {
	policy := DefaultPolicy()
	policy.DeniedCountries = []string{"US"}
	e, sink := lateralFixture(t, policy, 100)
	fact := Fact{Scope: testFact().Scope, Kind: "geo", SrcIP: "192.0.2.1", DstIP: "8.8.8.8", Value: "US|15169", Provenance: "dbip"}
	if err := e.Observe(testTime.Add(2*time.Second), fact); err != nil {
		t.Fatal(err)
	}
	if detectorCount(sink, "policy.geographic-country") != 1 || detectorCount(sink, "baseline.new-geo") != 1 {
		t.Fatal("geographic novelty/policy not detected")
	}
	if err := e.Change("approve-changes", []string{factID(fact)}, "region approved, separate policy retained"); err != nil {
		t.Fatal(err)
	}
	fact.DstIP = "8.8.4.4"
	fact.Provenance = "geolite2"
	if err := e.Observe(testTime.Add(3*time.Second), fact); err != nil {
		t.Fatal(err)
	}
	if detectorCount(sink, "baseline.new-geo") != 1 {
		t.Fatal("same country/ASN treated as novel for every destination")
	}
	if detectorCount(sink, "policy.geographic-country") != 2 {
		t.Fatal("baseline approval silently removed explicit deny policy")
	}
	if err := e.Change("suppress", []string{factID(fact)}, "documented policy exception"); err != nil {
		t.Fatal(err)
	}
	if err := e.Observe(testTime.Add(10*time.Minute), fact); err != nil {
		t.Fatal(err)
	}
	if detectorCount(sink, "policy.geographic-country") != 2 {
		t.Fatal("explicit suppression ignored")
	}
}
