package behavior

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestMaintenanceUsesCaptureTimeAndExpires(t *testing.T) {
	policy := DefaultPolicy()
	policy.Maintenance = []Maintenance{{Source: "192.0.2.1", Start: testTime.Add(2 * time.Second).UnixNano(), End: testTime.Add(10 * time.Second).UnixNano()}}
	e, sink := lateralFixture(t, policy, 100)
	for i := range 5 {
		if err := e.Observe(testTime.Add(time.Duration(i+2)*time.Second), attempt("192.0.2.1", "192.0.2.2", 22, "maintenance")); err != nil {
			t.Fatal(err)
		}
	}
	if len(sink.alerts) != 0 {
		t.Fatal("maintenance emitted expected administrative alerts")
	}
	if err := e.Observe(testTime.Add(10*time.Second), attempt("192.0.2.1", "192.0.2.3", 22, "after")); err != nil {
		t.Fatal(err)
	}
	if detectorCount(sink, "lateral.new-ssh-edge") != 1 {
		t.Fatal("maintenance did not expire at capture-time boundary")
	}
}

func TestPolicyFileDefaultsAndStrictValidation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.json")
	if err := os.WriteFile(path, []byte(`{"approvedSources":["192.0.2.0/24"],"deniedCountries":["US"]}`), 0600); err != nil {
		t.Fatal(err)
	}
	policy, err := LoadPolicy(path)
	if err != nil || policy.Fanout != 5 || policy.RateWindows != 4 || len(policy.DeniedCountries) != 1 {
		t.Fatalf("policy = %+v, %v", policy, err)
	}
	if err := os.WriteFile(path, []byte(`{"unknown":true}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPolicy(path); err == nil {
		t.Fatal("unknown policy field accepted")
	}
}
