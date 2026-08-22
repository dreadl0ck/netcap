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

package rules

import (
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/types"
)

func newDistinctEngine() *Engine {
	return &Engine{
		thresholdTrackers: make(map[string]*thresholdTracker),
		distinctTrackers:  make(map[string]*distinctTracker),
	}
}

// tcpAt builds a TCP record at a given timestamp for the given src/dst.
func tcpAt(ts int64, src, dst string) *types.TCP {
	return &types.TCP{Timestamp: ts, SrcIP: src, DstIP: dst, DstPort: 102}
}

// TestDistinctThreshold_FanOut verifies that one source touching many distinct
// destinations fires once the distinct count reaches the threshold, while a
// single source repeatedly hitting the same destination does not.
func TestDistinctThreshold_FanOut(t *testing.T) {
	engine := newDistinctEngine()
	rule := &Rule{
		Name:              "s7-enum",
		DistinctField:     "DstIP",
		DistinctThreshold: 3,
		ThresholdWindow:   300,
	}

	base := time.Now().UnixNano()

	// Same source hitting 2 distinct destinations: below threshold.
	if engine.checkDistinctThreshold(rule, tcpAt(base, "10.0.0.9", "10.0.1.1")) {
		t.Fatal("should not fire on first distinct destination")
	}
	if engine.checkDistinctThreshold(rule, tcpAt(base+1, "10.0.0.9", "10.0.1.2")) {
		t.Fatal("should not fire on second distinct destination")
	}
	// Repeat of an already-seen destination must NOT increase cardinality.
	if engine.checkDistinctThreshold(rule, tcpAt(base+2, "10.0.0.9", "10.0.1.1")) {
		t.Fatal("repeat destination should not push cardinality over threshold")
	}
	// Third distinct destination: fires.
	if !engine.checkDistinctThreshold(rule, tcpAt(base+3, "10.0.0.9", "10.0.1.3")) {
		t.Fatal("should fire on third distinct destination")
	}
}

// TestDistinctThreshold_PerSource verifies the count is keyed per source IP:
// two different sources each hitting one destination must not combine.
func TestDistinctThreshold_PerSource(t *testing.T) {
	engine := newDistinctEngine()
	rule := &Rule{
		Name:              "s7-enum",
		DistinctField:     "DstIP",
		DistinctThreshold: 2,
		ThresholdWindow:   300,
	}
	base := time.Now().UnixNano()

	if engine.checkDistinctThreshold(rule, tcpAt(base, "10.0.0.1", "10.0.1.1")) {
		t.Fatal("source A first dst should not fire")
	}
	if engine.checkDistinctThreshold(rule, tcpAt(base+1, "10.0.0.2", "10.0.1.2")) {
		t.Fatal("source B first dst should not fire (per-source keying)")
	}
	// Source A reaches 2 distinct -> fires; source B independent.
	if !engine.checkDistinctThreshold(rule, tcpAt(base+2, "10.0.0.1", "10.0.1.9")) {
		t.Fatal("source A second distinct dst should fire")
	}
}

// TestDistinctThreshold_WindowExpiry verifies that distinct values outside the
// window are pruned and do not count toward the threshold (using record time).
func TestDistinctThreshold_WindowExpiry(t *testing.T) {
	engine := newDistinctEngine()
	rule := &Rule{
		Name:              "s7-enum",
		DistinctField:     "DstIP",
		DistinctThreshold: 2,
		ThresholdWindow:   10, // 10 seconds
	}

	base := time.Now().UnixNano()
	tenSecs := int64(10) * int64(time.Second)

	if engine.checkDistinctThreshold(rule, tcpAt(base, "10.0.0.1", "10.0.1.1")) {
		t.Fatal("first should not fire")
	}
	// Second distinct destination 20s later: the first is now outside the
	// window, so cardinality is still only 1 -> no fire.
	if engine.checkDistinctThreshold(rule, tcpAt(base+2*tenSecs, "10.0.0.1", "10.0.1.2")) {
		t.Fatal("expired first value should not count toward threshold")
	}
}

// TestThreshold_UsesRecordTime verifies the raw-count threshold path uses the
// record's own timestamp so windows work on offline PCAP replay.
func TestThreshold_UsesRecordTime(t *testing.T) {
	engine := newDistinctEngine()
	rule := &Rule{
		Name:            "burst",
		Threshold:       3,
		ThresholdWindow: 5, // 5 seconds
	}

	// Three records within a 5s window in record time -> fires on the third.
	base := int64(1_000_000_000) * int64(time.Second) // arbitrary fixed epoch
	if engine.checkThreshold(rule, tcpAt(base, "10.0.0.1", "10.0.1.1")) {
		t.Fatal("first should not fire")
	}
	if engine.checkThreshold(rule, tcpAt(base+int64(time.Second), "10.0.0.1", "10.0.1.1")) {
		t.Fatal("second should not fire")
	}
	if !engine.checkThreshold(rule, tcpAt(base+2*int64(time.Second), "10.0.0.1", "10.0.1.1")) {
		t.Fatal("third within window should fire")
	}
}

// TestThreshold_RecordTimeWindowExpiry verifies old matches (by record time)
// are pruned even though wall-clock time has not advanced.
func TestThreshold_RecordTimeWindowExpiry(t *testing.T) {
	engine := newDistinctEngine()
	rule := &Rule{
		Name:            "burst",
		Threshold:       2,
		ThresholdWindow: 5,
	}
	base := int64(1_000_000_000) * int64(time.Second)

	if engine.checkThreshold(rule, tcpAt(base, "10.0.0.1", "10.0.1.1")) {
		t.Fatal("first should not fire")
	}
	// 60s later in record time: first match is pruned, so still only 1 -> no fire.
	if engine.checkThreshold(rule, tcpAt(base+60*int64(time.Second), "10.0.0.1", "10.0.1.1")) {
		t.Fatal("match outside record-time window should not accumulate")
	}
}

func TestExtractStringField(t *testing.T) {
	rec := &types.TCP{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", DstPort: 102}
	if got := extractStringField(rec, "DstIP"); got != "10.0.0.2" {
		t.Errorf("DstIP = %q, want 10.0.0.2", got)
	}
	if got := extractStringField(rec, "DstPort"); got != "102" {
		t.Errorf("DstPort = %q, want 102", got)
	}
	if got := extractStringField(rec, "NoSuchField"); got != "" {
		t.Errorf("missing field = %q, want empty", got)
	}
}
