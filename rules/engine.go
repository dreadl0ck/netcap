/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) 2017-2020 Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

package rules

import (
	"fmt"
	"sync"
	"time"

	"github.com/dreadl0ck/netcap/types"
)

// Engine manages rules and evaluates them against audit records.
type Engine struct {
	config      *Config
	alertWriter AlertWriter

	// Deduplication tracking
	recentAlerts map[string]int64 // map[alertKey]lastSeen
	dedupWindow  time.Duration
	mu           sync.RWMutex

	// Rate limiting
	ruleCounters map[string]*rateCounter
	rateLimit    int // max alerts per minute per rule

	// Threshold tracking
	thresholdTrackers map[string]*thresholdTracker // map[ruleName]tracker
}

// rateCounter tracks alert counts for rate limiting.
type rateCounter struct {
	count       int
	windowStart time.Time
	mu          sync.Mutex
}

// thresholdTracker tracks rule matches for threshold-based alerting.
type thresholdTracker struct {
	matches     []int64 // timestamps of matches
	mu          sync.Mutex
}

// NewEngine creates a new rules engine with the given configuration and alert writer.
func NewEngine(rulesPath string, alertWriter AlertWriter) (*Engine, error) {
	if alertWriter == nil {
		return nil, fmt.Errorf("alert writer cannot be nil")
	}

	// Load rules from file
	config, err := LoadRulesFromFile(rulesPath)
	if err != nil {
		return nil, err
	}

	// Compile all rules
	err = CompileRules(config)
	if err != nil {
		return nil, err
	}

	engine := &Engine{
		config:            config,
		alertWriter:       alertWriter,
		recentAlerts:      make(map[string]int64),
		dedupWindow:       5 * time.Minute, // Default 5 minute deduplication window
		ruleCounters:      make(map[string]*rateCounter),
		rateLimit:         100, // Default 100 alerts per minute per rule
		thresholdTrackers: make(map[string]*thresholdTracker),
	}

	return engine, nil
}

// SetDeduplicationWindow configures the time window for alert deduplication.
func (e *Engine) SetDeduplicationWindow(d time.Duration) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.dedupWindow = d
}

// SetRateLimit configures the maximum number of alerts per minute per rule.
func (e *Engine) SetRateLimit(limit int) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.rateLimit = limit
}

// Evaluate evaluates all applicable rules against an audit record.
// It returns the number of alerts generated.
func (e *Engine) Evaluate(record types.AuditRecord) (int, error) {
	recordType := record.NetcapType()
	alertCount := 0

	for _, rule := range e.config.Rules {
		if !rule.Enabled {
			continue
		}

		// Check if rule applies to this record type
		ruleType, err := parseRecordType(rule.Type)
		if err != nil {
			continue
		}

		if ruleType != recordType {
			continue
		}

		// Evaluate the rule
		alert, err := EvaluateRule(rule, record)
		if err != nil {
			return alertCount, fmt.Errorf("error evaluating rule %s: %w", rule.Name, err)
		}

		if alert == nil {
			continue
		}

		// Check threshold - if rule has threshold > 1, track matches
		if rule.Threshold > 1 {
			thresholdReached := e.checkThreshold(rule)
			if !thresholdReached {
				// Threshold not reached yet, don't generate alert
				continue
			}
			// For threshold-based rules, skip deduplication since the threshold
			// itself provides rate limiting. The threshold tracker already ensures
			// we don't alert too frequently, and we want to alert each time the
			// threshold is reached (not just once per dedup window).
		} else {
			// Check deduplication only for non-threshold rules
			if e.isDuplicate(alert) {
				continue
			}
		}

		// Check rate limiting
		if e.isRateLimited(rule.Name) {
			continue
		}

		// Write the alert
		err = e.alertWriter.WriteAlert(alert)
		if err != nil {
			return alertCount, fmt.Errorf("error writing alert: %w", err)
		}

		alertCount++
	}

	return alertCount, nil
}

// isDuplicate checks if an alert is a duplicate within the deduplication window.
func (e *Engine) isDuplicate(alert *types.Alert) bool {
	e.mu.Lock()
	defer e.mu.Unlock()

	// Create a key for deduplication
	key := fmt.Sprintf("%s:%s:%s:%s", alert.RuleName, alert.SrcIP, alert.DstIP, alert.RecordType)

	now := time.Now().UnixNano()
	lastSeen, exists := e.recentAlerts[key]

	if exists {
		// Check if within deduplication window
		if time.Duration(now-lastSeen) < e.dedupWindow {
			return true
		}
	}

	// Update last seen time
	e.recentAlerts[key] = now

	// Cleanup old entries (every 100 alerts)
	if len(e.recentAlerts)%100 == 0 {
		e.cleanupRecentAlerts()
	}

	return false
}

// cleanupRecentAlerts removes old entries from the deduplication map.
func (e *Engine) cleanupRecentAlerts() {
	now := time.Now().UnixNano()
	for key, lastSeen := range e.recentAlerts {
		if time.Duration(now-lastSeen) > e.dedupWindow {
			delete(e.recentAlerts, key)
		}
	}
}

// checkThreshold tracks rule matches and returns true when threshold is reached.
func (e *Engine) checkThreshold(rule *Rule) bool {
	e.mu.Lock()
	tracker, exists := e.thresholdTrackers[rule.Name]
	if !exists {
		tracker = &thresholdTracker{
			matches: make([]int64, 0),
		}
		e.thresholdTrackers[rule.Name] = tracker
	}
	e.mu.Unlock()

	tracker.mu.Lock()
	defer tracker.mu.Unlock()

	now := time.Now().UnixNano()

	// Handle edge case: threshold <= 0 should never trigger
	if rule.Threshold <= 0 {
		return false
	}

	// Default threshold window is 60 seconds if not specified
	windowSeconds := rule.ThresholdWindow
	if windowSeconds <= 0 {
		windowSeconds = 60
	}
	windowNanos := int64(windowSeconds) * int64(time.Second)

	// Remove matches outside the time window
	validMatches := make([]int64, 0)
	for _, matchTime := range tracker.matches {
		if now-matchTime <= windowNanos {
			validMatches = append(validMatches, matchTime)
		}
	}

	// Add current match
	validMatches = append(validMatches, now)
	tracker.matches = validMatches

	// Check if threshold is reached
	if len(tracker.matches) >= rule.Threshold {
		// Threshold reached - reset the tracker and return true
		tracker.matches = make([]int64, 0)
		return true
	}

	// Threshold not yet reached
	return false
}

// isRateLimited checks if a rule has exceeded its rate limit.
func (e *Engine) isRateLimited(ruleName string) bool {
	e.mu.Lock()
	counter, exists := e.ruleCounters[ruleName]
	if !exists {
		counter = &rateCounter{
			count:       0,
			windowStart: time.Now(),
		}
		e.ruleCounters[ruleName] = counter
	}
	e.mu.Unlock()

	counter.mu.Lock()
	defer counter.mu.Unlock()

	now := time.Now()

	// Reset counter if window has passed
	if now.Sub(counter.windowStart) >= time.Minute {
		counter.count = 0
		counter.windowStart = now
	}

	// Check if rate limit exceeded
	if counter.count >= e.rateLimit {
		return true
	}

	counter.count++
	return false
}

// GetStats returns statistics about the engine.
func (e *Engine) GetStats() map[string]interface{} {
	e.mu.RLock()
	defer e.mu.RUnlock()

	enabledRules := 0
	thresholdRules := 0
	for _, rule := range e.config.Rules {
		if rule.Enabled {
			enabledRules++
		}
		if rule.Threshold > 1 {
			thresholdRules++
		}
	}

	return map[string]interface{}{
		"total_rules":      len(e.config.Rules),
		"enabled_rules":    enabledRules,
		"threshold_rules":  thresholdRules,
		"recent_alerts":    len(e.recentAlerts),
		"dedup_window":     e.dedupWindow.String(),
		"rate_limit":       e.rateLimit,
		"tracked_thresholds": len(e.thresholdTrackers),
	}
}

// UpdateConfig updates the rules configuration in memory.
// This allows for runtime updates of rules without recreating the engine.
func (e *Engine) UpdateConfig(config *Config) error {
	// Compile all rules in the new config
	err := CompileRules(config)
	if err != nil {
		return fmt.Errorf("failed to compile rules: %w", err)
	}

	// Update config atomically
	e.mu.Lock()
	e.config = config
	e.mu.Unlock()

	return nil
}

// Close closes the alert writer.
func (e *Engine) Close() error {
	if closer, ok := e.alertWriter.(interface{ Close() error }); ok {
		return closer.Close()
	}
	return nil
}
