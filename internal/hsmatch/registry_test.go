/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 */

package hsmatch

import (
	"reflect"
	"testing"
)

func TestRegistry_RegisterSnapshotAndUnregister(t *testing.T) {
	UnregisterSubsystem("alpha")
	UnregisterSubsystem("zulu")
	UnregisterSubsystem("mike")
	defer func() {
		UnregisterSubsystem("alpha")
		UnregisterSubsystem("zulu")
		UnregisterSubsystem("mike")
	}()

	RegisterSubsystem(SubsystemFunc{N: "zulu", F: func() any { return "z" }})
	RegisterSubsystem(SubsystemFunc{N: "alpha", F: func() any { return 1 }})
	RegisterSubsystem(SubsystemFunc{N: "mike", F: func() any { return map[string]int{"k": 7} }})

	snaps := Snapshot()
	if got, want := len(snaps), 3; got < want {
		t.Fatalf("expected at least %d snapshots, got %d", want, got)
	}

	// Pick out only our three to avoid being noisy if other tests register.
	got := make(map[string]any, 3)
	for _, s := range snaps {
		switch s.Name {
		case "alpha", "mike", "zulu":
			got[s.Name] = s.Data
		}
	}
	want := map[string]any{
		"alpha": 1,
		"mike":  map[string]int{"k": 7},
		"zulu":  "z",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("snapshot mismatch:\n got=%#v\nwant=%#v", got, want)
	}

	// Snapshot must be sorted.
	var seen []string
	for _, s := range snaps {
		if s.Name == "alpha" || s.Name == "mike" || s.Name == "zulu" {
			seen = append(seen, s.Name)
		}
	}
	if !sortedStrings(seen) {
		t.Fatalf("snapshot order not sorted: %v", seen)
	}

	UnregisterSubsystem("alpha")
	for _, s := range Snapshot() {
		if s.Name == "alpha" {
			t.Fatalf("alpha still present after Unregister")
		}
	}
}

func TestRegistry_IgnoresNilAndEmptyName(t *testing.T) {
	before := len(Snapshot())
	RegisterSubsystem(nil)
	RegisterSubsystem(SubsystemFunc{N: "", F: func() any { return nil }})
	if got := len(Snapshot()); got != before {
		t.Fatalf("expected snapshot count to be unchanged, got %d (was %d)", got, before)
	}
}

func TestRegistry_SnapshotMap(t *testing.T) {
	UnregisterSubsystem("xx-test")
	defer UnregisterSubsystem("xx-test")
	RegisterSubsystem(SubsystemFunc{N: "xx-test", F: func() any { return 42 }})
	m := SnapshotMap()
	if v, ok := m["xx-test"]; !ok || v != 42 {
		t.Fatalf("expected SnapshotMap[\"xx-test\"]==42, got %v ok=%v", v, ok)
	}
}

func sortedStrings(s []string) bool {
	for i := 1; i < len(s); i++ {
		if s[i-1] > s[i] {
			return false
		}
	}
	return true
}
