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

package performance

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestTrackerFilterMetrics(t *testing.T) {
	tracker := NewTracker()

	// Record some filter evaluations
	tracker.RecordFilterEvaluation(100*time.Microsecond, false) // not filtered
	tracker.RecordFilterEvaluation(150*time.Microsecond, true)  // filtered
	tracker.RecordFilterEvaluation(200*time.Microsecond, true)  // filtered

	// Check metrics
	if tracker.FilterEvaluations != 3 {
		t.Errorf("expected 3 filter evaluations, got %d", tracker.FilterEvaluations)
	}

	if tracker.FilteredRecords != 2 {
		t.Errorf("expected 2 filtered records, got %d", tracker.FilteredRecords)
	}

	expectedNs := int64(100+150+200) * int64(time.Microsecond)
	if tracker.FilterEvaluationsNs != expectedNs {
		t.Errorf("expected %d ns, got %d ns", expectedNs, tracker.FilterEvaluationsNs)
	}
}

func TestTrackerRulesMetrics(t *testing.T) {
	tracker := NewTracker()

	// Record some rules evaluations
	tracker.RecordRulesEvaluation(100*time.Microsecond, 0) // no alerts
	tracker.RecordRulesEvaluation(150*time.Microsecond, 1) // 1 alert
	tracker.RecordRulesEvaluation(200*time.Microsecond, 2) // 2 alerts

	// Check metrics
	if tracker.RulesEvaluations != 3 {
		t.Errorf("expected 3 rules evaluations, got %d", tracker.RulesEvaluations)
	}

	if tracker.AlertsGenerated != 3 {
		t.Errorf("expected 3 alerts generated, got %d", tracker.AlertsGenerated)
	}

	expectedNs := int64(100+150+200) * int64(time.Microsecond)
	if tracker.RulesEvaluationsNs != expectedNs {
		t.Errorf("expected %d ns, got %d ns", expectedNs, tracker.RulesEvaluationsNs)
	}
}

func TestTrackerReportWithFilterAndRules(t *testing.T) {
	tracker := NewTracker()

	// Set up some test data
	tracker.SetTotalPacketsAndBytes(1000, 500000)

	// Add some filter metrics
	for i := 0; i < 100; i++ {
		tracker.RecordFilterEvaluation(10*time.Microsecond, i%3 == 0) // 33% filtered
	}

	// Add some rules metrics
	for i := 0; i < 100; i++ {
		alerts := 0
		if i%10 == 0 {
			alerts = 1
		}
		tracker.RecordRulesEvaluation(20*time.Microsecond, alerts) // 10% alert rate
	}

	// Write report to temp file
	tmpDir := t.TempDir()
	reportPath := filepath.Join(tmpDir, "performance_test.log")

	err := tracker.WriteReport(reportPath)
	if err != nil {
		t.Fatalf("failed to write report: %v", err)
	}

	// Read and verify report contents
	content, err := os.ReadFile(reportPath)
	if err != nil {
		t.Fatalf("failed to read report: %v", err)
	}

	reportStr := string(content)

	// Verify filter section exists
	if !strings.Contains(reportStr, "FILTER PERFORMANCE") {
		t.Error("report should contain FILTER PERFORMANCE section")
	}
	if !strings.Contains(reportStr, "Filter Evaluations:   100") {
		t.Error("report should show 100 filter evaluations")
	}

	// Verify rules section exists
	if !strings.Contains(reportStr, "RULES ENGINE PERFORMANCE") {
		t.Error("report should contain RULES ENGINE PERFORMANCE section")
	}
	if !strings.Contains(reportStr, "Rules Evaluations:    100") {
		t.Error("report should show 100 rules evaluations")
	}
	if !strings.Contains(reportStr, "Alerts Generated:     10") {
		t.Error("report should show 10 alerts generated")
	}

	// Verify processing overhead is calculated
	if !strings.Contains(reportStr, "Processing Overhead:") {
		t.Error("report should contain processing overhead calculation")
	}
}

func TestTrackerNoFilterOrRules(t *testing.T) {
	tracker := NewTracker()

	// Set up packet data but no filter/rules data
	tracker.SetTotalPacketsAndBytes(1000, 500000)

	// Write report to temp file
	tmpDir := t.TempDir()
	reportPath := filepath.Join(tmpDir, "performance_test.log")

	err := tracker.WriteReport(reportPath)
	if err != nil {
		t.Fatalf("failed to write report: %v", err)
	}

	// Read and verify report contents
	content, err := os.ReadFile(reportPath)
	if err != nil {
		t.Fatalf("failed to read report: %v", err)
	}

	reportStr := string(content)

	// Verify filter and rules sections don't exist when no data
	if strings.Contains(reportStr, "FILTER PERFORMANCE") {
		t.Error("report should not contain FILTER PERFORMANCE section when no filter data")
	}
	if strings.Contains(reportStr, "RULES ENGINE PERFORMANCE") {
		t.Error("report should not contain RULES ENGINE PERFORMANCE section when no rules data")
	}
}
