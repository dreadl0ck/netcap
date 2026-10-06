package behavior

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHealthBoundsUnknownCountersAndStorageFailure(t *testing.T) {
	dir := t.TempDir()
	state := Snapshot{Observed: map[string]Observation{}, Error: "disk full"}
	for i := range 200 {
		state.Observed[fmt.Sprint(i)] = Observation{Fact: Fact{Scope: Scope{Sensor: "test", Interface: fmt.Sprint(i)}}}
	}
	health := BuildHealth(state, filepath.Join(dir, "missing"), dir, false, nil, nil)
	if !health.ScopesTruncated || len(health.Scopes) != 128 || health.Capture != nil || health.Delivery != nil || health.BaselineBytes != nil || health.StorageError == "" || health.DetectorError != "disk full" {
		t.Fatalf("health hides unknown counters or storage failure: %+v", health)
	}
	if err := WriteHealth(dir, health); err != nil {
		t.Fatal(err)
	}
	stored, err := ReadHealth(dir)
	if err != nil || stored.Active || len(stored.Scopes) != 128 || stored.Capture != nil {
		t.Fatalf("retained health: %+v, %v", stored, err)
	}
	for id, observation := range state.Observed {
		observation.Fact.Scope.Sensor = strings.Repeat("&", 256)
		state.Observed[id] = observation
	}
	wide := BuildHealth(state, filepath.Join(dir, "missing"), dir, false, nil, nil)
	if !wide.ScopesTruncated || len(wide.Scopes) >= 128 {
		t.Fatal("escaped scope names bypassed the byte bound")
	}
	if err := WriteHealth(dir, wide); err != nil {
		t.Fatal("valid large scopes broke health persistence", err)
	}
	for _, data := range []string{`{"schema":2}`, "{", strings.Repeat(" ", (64<<10)+1)} {
		if err := os.WriteFile(filepath.Join(dir, "BehaviorHealth.json"), []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := ReadHealth(dir); err == nil {
			t.Fatal("invalid/oversized health accepted")
		}
	}
}
