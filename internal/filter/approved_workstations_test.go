/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package filter

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/types"
)

func TestApprovedWorkstations(t *testing.T) {
	// Ensure a clean state and restore it afterwards.
	t.Cleanup(func() { SetApprovedWorkstations(nil) })

	t.Run("empty allowlist treats every source as non-approved", func(t *testing.T) {
		SetApprovedWorkstations(nil)
		if IsApprovedWorkstation("10.0.0.5") {
			t.Fatal("expected empty allowlist to return false")
		}
		if InAllowlist("10.0.0.5") {
			t.Fatal("expected empty allowlist to return false for InAllowlist")
		}
	})

	t.Run("set and query", func(t *testing.T) {
		SetApprovedWorkstations([]string{"10.0.0.5", " 10.0.0.6 ", ""})
		if !IsApprovedWorkstation("10.0.0.5") {
			t.Error("10.0.0.5 should be approved")
		}
		if !IsApprovedWorkstation("10.0.0.6") {
			t.Error("10.0.0.6 should be approved (whitespace trimmed)")
		}
		if IsApprovedWorkstation("10.0.0.99") {
			t.Error("10.0.0.99 should NOT be approved")
		}
		if !InAllowlist("10.0.0.5") {
			t.Error("InAllowlist alias should agree with IsApprovedWorkstation")
		}
	})

	t.Run("set replaces previous contents", func(t *testing.T) {
		SetApprovedWorkstations([]string{"10.0.0.5"})
		SetApprovedWorkstations([]string{"10.0.0.7"})
		if IsApprovedWorkstation("10.0.0.5") {
			t.Error("previous entry should have been replaced")
		}
		if !IsApprovedWorkstation("10.0.0.7") {
			t.Error("new entry should be present")
		}
	})
}

func TestLoadApprovedWorkstationsFromFile(t *testing.T) {
	t.Cleanup(func() { SetApprovedWorkstations(nil) })

	dir := t.TempDir()
	path := filepath.Join(dir, "approved.csv")

	content := "" +
		"# approved engineering workstations\n" +
		"* comment style two\n" +
		"\n" +
		"10.0.0.5\n" + // bare IP
		"eng-ws-01,10.0.0.6\n" + // name,ip CSV
		"  10.0.0.7  \n" + // whitespace
		"site,rack,10.0.0.8\n" // multi-field CSV, last field is IP

	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := LoadApprovedWorkstationsFromFile(path); err != nil {
		t.Fatalf("load failed: %v", err)
	}

	for _, ip := range []string{"10.0.0.5", "10.0.0.6", "10.0.0.7", "10.0.0.8"} {
		if !IsApprovedWorkstation(ip) {
			t.Errorf("expected %s to be approved after load", ip)
		}
	}

	if IsApprovedWorkstation("eng-ws-01") {
		t.Error("hostname token should not be treated as an approved IP")
	}
}

func TestLoadApprovedWorkstationsFromFile_Missing(t *testing.T) {
	if err := LoadApprovedWorkstationsFromFile(filepath.Join(t.TempDir(), "nope.csv")); err == nil {
		t.Fatal("expected error for missing file")
	}
}

// TestApprovedWorkstationHelperInExpression verifies the helper is wired into
// the expression engine and usable in a rule expression, including negation.
func TestApprovedWorkstationHelperInExpression(t *testing.T) {
	t.Cleanup(func() { SetApprovedWorkstations(nil) })
	SetApprovedWorkstations([]string{"10.0.0.5"})

	prog, err := CompileExpression("FunctionCode == 5 && !IsApprovedWorkstation(SrcIP)", types.Type_NC_S7Comm)
	if err != nil {
		t.Fatalf("compile failed: %v", err)
	}
	if prog == nil {
		t.Fatal("expected a compiled program")
	}
}

func TestTemporalHelpers(t *testing.T) {
	// Wednesday 2024-01-03 14:30 local time.
	wedAfternoon := time.Date(2024, 1, 3, 14, 30, 0, 0, time.Local).UnixNano()
	// Wednesday 2024-01-03 22:00 local time (off-hours).
	wedNight := time.Date(2024, 1, 3, 22, 0, 0, 0, time.Local).UnixNano()
	// Saturday 2024-01-06 14:30 local time (weekend).
	satAfternoon := time.Date(2024, 1, 6, 14, 30, 0, 0, time.Local).UnixNano()

	if got := HourOfDay(wedAfternoon); got != 14 {
		t.Errorf("HourOfDay = %d, want 14", got)
	}
	if got := Weekday(wedAfternoon); got != int(time.Wednesday) {
		t.Errorf("Weekday = %d, want %d", got, int(time.Wednesday))
	}

	if !IsBusinessHours(wedAfternoon, 8, 18) {
		t.Error("Wed 14:30 should be business hours")
	}
	if IsBusinessHours(wedNight, 8, 18) {
		t.Error("Wed 22:00 should NOT be business hours")
	}
	if IsBusinessHours(satAfternoon, 8, 18) {
		t.Error("Saturday should NOT be business hours")
	}
}

func TestTemporalHelpersInExpression(t *testing.T) {
	prog, err := CompileExpression("IsCriticalOperation && !IsBusinessHours(Timestamp, 8, 18)", types.Type_NC_S7Comm)
	if err != nil {
		t.Fatalf("compile failed: %v", err)
	}
	if prog == nil {
		t.Fatal("expected a compiled program")
	}
}
