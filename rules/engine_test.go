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
)

// TestCheckThreshold_BasicBehavior tests basic threshold functionality.
func TestCheckThreshold_BasicBehavior(t *testing.T) {
	engine := &Engine{
		thresholdTrackers: make(map[string]*thresholdTracker),
	}

	rule := &Rule{
		Name:            "test-rule",
		Threshold:       3,
		ThresholdWindow: 60, // 60 seconds
	}

	// First match - should return false
	if engine.checkThreshold(rule, nil) {
		t.Error("Expected false on first match, got true")
	}

	// Second match - should return false
	if engine.checkThreshold(rule, nil) {
		t.Error("Expected false on second match, got true")
	}

	// Third match - should return true (threshold reached)
	if !engine.checkThreshold(rule, nil) {
		t.Error("Expected true on third match (threshold reached), got false")
	}

	// Fourth match - should return false (tracker was reset)
	if engine.checkThreshold(rule, nil) {
		t.Error("Expected false on fourth match (after reset), got true")
	}
}

// TestCheckThreshold_DefaultWindow tests that default window is applied when not specified.
func TestCheckThreshold_DefaultWindow(t *testing.T) {
	engine := &Engine{
		thresholdTrackers: make(map[string]*thresholdTracker),
	}

	rule := &Rule{
		Name:            "test-rule-default",
		Threshold:       2,
		ThresholdWindow: 0, // Should default to 60 seconds
	}

	// First match
	engine.checkThreshold(rule, nil)

	// Verify that tracker was created and has a match
	tracker, exists := engine.thresholdTrackers[rule.Name]
	if !exists {
		t.Fatal("Tracker was not created")
	}

	if len(tracker.matches) != 1 {
		t.Errorf("Expected 1 match, got %d", len(tracker.matches))
	}
}

// TestCheckThreshold_TimeWindow tests that old matches are removed outside the time window.
func TestCheckThreshold_TimeWindow(t *testing.T) {
	engine := &Engine{
		thresholdTrackers: make(map[string]*thresholdTracker),
	}

	rule := &Rule{
		Name:            "test-rule-window",
		Threshold:       3,
		ThresholdWindow: 1, // 1 second window
	}

	// Add first match
	engine.checkThreshold(rule, nil)

	// Add second match
	engine.checkThreshold(rule, nil)

	// Wait for window to expire
	time.Sleep(1100 * time.Millisecond)

	// Add third match - first two should be expired
	// Should return false because old matches are removed
	if engine.checkThreshold(rule, nil) {
		t.Error("Expected false because old matches should be outside time window")
	}

	// Verify only 1 match remains
	tracker := engine.thresholdTrackers[rule.Name]
	if len(tracker.matches) != 1 {
		t.Errorf("Expected 1 match after window expiry, got %d", len(tracker.matches))
	}
}

// TestCheckThreshold_MultipleRules tests that different rules track independently.
func TestCheckThreshold_MultipleRules(t *testing.T) {
	engine := &Engine{
		thresholdTrackers: make(map[string]*thresholdTracker),
	}

	rule1 := &Rule{
		Name:            "rule-1",
		Threshold:       2,
		ThresholdWindow: 60,
	}

	rule2 := &Rule{
		Name:            "rule-2",
		Threshold:       3,
		ThresholdWindow: 60,
	}

	// Add match to rule1
	engine.checkThreshold(rule1, nil)

	// Add match to rule2
	engine.checkThreshold(rule2, nil)

	// Verify independent tracking
	tracker1 := engine.thresholdTrackers[rule1.Name]
	tracker2 := engine.thresholdTrackers[rule2.Name]

	if len(tracker1.matches) != 1 {
		t.Errorf("Rule 1: Expected 1 match, got %d", len(tracker1.matches))
	}

	if len(tracker2.matches) != 1 {
		t.Errorf("Rule 2: Expected 1 match, got %d", len(tracker2.matches))
	}

	// Reach threshold for rule1
	if !engine.checkThreshold(rule1, nil) {
		t.Error("Rule 1: Expected threshold to be reached on second match")
	}

	// rule2 should still have only 1 match
	if len(tracker2.matches) != 1 {
		t.Errorf("Rule 2: Expected 1 match (should be unaffected), got %d", len(tracker2.matches))
	}
}

// TestCheckThreshold_ImmediateReset tests that tracker is reset immediately after threshold is reached.
func TestCheckThreshold_ImmediateReset(t *testing.T) {
	engine := &Engine{
		thresholdTrackers: make(map[string]*thresholdTracker),
	}

	rule := &Rule{
		Name:            "test-rule-reset",
		Threshold:       2,
		ThresholdWindow: 60,
	}

	// First match
	engine.checkThreshold(rule, nil)

	// Second match - reaches threshold
	if !engine.checkThreshold(rule, nil) {
		t.Fatal("Expected threshold to be reached")
	}

	// Verify tracker was reset
	tracker := engine.thresholdTrackers[rule.Name]
	if len(tracker.matches) != 0 {
		t.Errorf("Expected tracker to be reset (0 matches), got %d", len(tracker.matches))
	}

	// Next match should start fresh
	if engine.checkThreshold(rule, nil) {
		t.Error("Expected false after reset (fresh start), got true")
	}

	if len(tracker.matches) != 1 {
		t.Errorf("Expected 1 match after fresh start, got %d", len(tracker.matches))
	}
}

// TestCheckThreshold_ConcurrentAccess tests thread-safety of threshold checking.
func TestCheckThreshold_ConcurrentAccess(t *testing.T) {
	engine := &Engine{
		thresholdTrackers: make(map[string]*thresholdTracker),
	}

	rule := &Rule{
		Name:            "test-concurrent",
		Threshold:       100,
		ThresholdWindow: 10,
	}

	// Run concurrent threshold checks
	done := make(chan bool, 50)
	for range 50 {
		go func() {
			engine.checkThreshold(rule, nil)
			done <- true
		}()
	}

	// Wait for all goroutines
	for range 50 {
		<-done
	}

	// Verify tracker exists and has some matches
	tracker, exists := engine.thresholdTrackers[rule.Name]
	if !exists {
		t.Fatal("Tracker was not created")
	}

	if len(tracker.matches) == 0 {
		t.Error("Expected some matches to be recorded")
	}

	// The exact number may vary due to timing, but should be <= 50
	if len(tracker.matches) > 50 {
		t.Errorf("Expected at most 50 matches, got %d", len(tracker.matches))
	}
}

// TestCheckThreshold_EdgeCases tests edge cases and boundary conditions.
func TestCheckThreshold_EdgeCases(t *testing.T) {
	tests := []struct {
		name            string
		threshold       int
		window          int
		matches         int
		expectedTrigger bool
		description     string
	}{
		{
			name:            "threshold-1",
			threshold:       1,
			window:          60,
			matches:         1,
			expectedTrigger: true,
			description:     "Threshold of 1 should trigger on first match",
		},
		{
			name:            "threshold-0",
			threshold:       0,
			window:          60,
			matches:         1,
			expectedTrigger: false,
			description:     "Threshold of 0 should never trigger",
		},
		{
			name:            "large-threshold",
			threshold:       1000,
			window:          60,
			matches:         100,
			expectedTrigger: false,
			description:     "Large threshold should not trigger with fewer matches",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			engine := &Engine{
				thresholdTrackers: make(map[string]*thresholdTracker),
			}

			rule := &Rule{
				Name:            tt.name,
				Threshold:       tt.threshold,
				ThresholdWindow: tt.window,
			}

			var triggered bool
			for i := 0; i < tt.matches; i++ {
				if engine.checkThreshold(rule, nil) {
					triggered = true
					break
				}
			}

			if triggered != tt.expectedTrigger {
				t.Errorf("%s: Expected trigger=%v, got trigger=%v",
					tt.description, tt.expectedTrigger, triggered)
			}
		})
	}
}

// TestCheckThreshold_WindowBoundary tests behavior at window boundaries.
func TestCheckThreshold_WindowBoundary(t *testing.T) {
	engine := &Engine{
		thresholdTrackers: make(map[string]*thresholdTracker),
	}

	rule := &Rule{
		Name:            "test-boundary",
		Threshold:       3,
		ThresholdWindow: 1, // 1 second
	}

	// Add first match
	engine.checkThreshold(rule, nil)

	// Wait just under the window
	time.Sleep(900 * time.Millisecond)

	// Add second match (should still be within window)
	engine.checkThreshold(rule, nil)

	// Verify 2 matches
	tracker := engine.thresholdTrackers[rule.Name]
	if len(tracker.matches) != 2 {
		t.Errorf("Expected 2 matches within window, got %d", len(tracker.matches))
	}

	// Wait for first match to expire
	time.Sleep(200 * time.Millisecond)

	// Add third match - first should be expired, second still valid
	engine.checkThreshold(rule, nil)

	// Should have 2 matches now (second + third)
	if len(tracker.matches) != 2 {
		t.Errorf("Expected 2 matches after boundary, got %d", len(tracker.matches))
	}
}

// TestCheckThreshold_ZeroWindow tests behavior with zero/negative window.
func TestCheckThreshold_ZeroWindow(t *testing.T) {
	engine := &Engine{
		thresholdTrackers: make(map[string]*thresholdTracker),
	}

	rule := &Rule{
		Name:            "test-zero-window",
		Threshold:       2,
		ThresholdWindow: 0, // Should default to 60
	}

	// Add two matches quickly
	engine.checkThreshold(rule, nil)
	reached := engine.checkThreshold(rule, nil)

	if !reached {
		t.Error("Expected threshold to be reached with default window")
	}

	// Test negative window (should also default to 60)
	rule2 := &Rule{
		Name:            "test-negative-window",
		Threshold:       2,
		ThresholdWindow: -10,
	}

	engine.checkThreshold(rule2, nil)
	reached2 := engine.checkThreshold(rule2, nil)

	if !reached2 {
		t.Error("Expected threshold to be reached with negative window (defaulted)")
	}
}
