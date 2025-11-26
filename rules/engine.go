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
	"os"
	"sync"
	"time"

	"github.com/dreadl0ck/netcap/firewall"
	"github.com/dreadl0ck/netcap/performance"
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

	// Performance tracking
	perfTracker *performance.Tracker

	// Firewall manager for response actions
	firewallManager *firewall.Manager

	// Response action statistics
	actionStats *ActionStats
}

// ActionStats tracks response action statistics.
type ActionStats struct {
	mu              sync.Mutex
	ActionsExecuted uint64
	ActionsSuccess  uint64
	ActionsFailed   uint64
	IPsBlocked      uint64
}

// rateCounter tracks alert counts for rate limiting.
type rateCounter struct {
	count       int
	windowStart time.Time
	mu          sync.Mutex
}

// thresholdTracker tracks rule matches for threshold-based alerting.
type thresholdTracker struct {
	matches []int64 // timestamps of matches
	mu      sync.Mutex
}

// NewEngine creates a new rules engine with the given configuration and alert writer.
// rulesPath can be a path to a single YAML file or a directory containing multiple YAML files.
func NewEngine(rulesPath string, alertWriter AlertWriter) (*Engine, error) {
	if alertWriter == nil {
		return nil, fmt.Errorf("alert writer cannot be nil")
	}

	// Check if path is a directory or file
	info, err := os.Stat(rulesPath)
	if err != nil {
		return nil, fmt.Errorf("failed to stat rules path: %w", err)
	}

	var config *Config
	if info.IsDir() {
		config, err = LoadRulesFromDirectory(rulesPath)
	} else {
		config, err = LoadRulesFromFile(rulesPath)
	}

	if err != nil {
		return nil, err
	}

	return NewEngineFromConfig(config, alertWriter)
}

// NewEngineFromConfig creates a new rules engine from an existing configuration.
// This allows creating an engine without reading from a file.
func NewEngineFromConfig(config *Config, alertWriter AlertWriter) (*Engine, error) {
	if alertWriter == nil {
		return nil, fmt.Errorf("alert writer cannot be nil")
	}

	// Compile all rules
	if err := CompileRules(config); err != nil {
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
		actionStats:       &ActionStats{},
	}

	return engine, nil
}

// SetFirewallManager sets the firewall manager for response actions.
// If not set, iptables-based response actions will be skipped.
func (e *Engine) SetFirewallManager(manager *firewall.Manager) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.firewallManager = manager
}

// GetFirewallManager returns the current firewall manager.
func (e *Engine) GetFirewallManager() *firewall.Manager {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.firewallManager
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

// SetPerformanceTracker sets the performance tracker for collecting metrics.
func (e *Engine) SetPerformanceTracker(tracker *performance.Tracker) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.perfTracker = tracker
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

		// Start timing for this rule
		ruleStart := time.Now()

		// Evaluate the rule
		alert, err := EvaluateRule(rule, record)
		if err != nil {
			return alertCount, fmt.Errorf("error evaluating rule %s: %w", rule.Name, err)
		}

		matched := alert != nil
		alertGenerated := false

		if alert != nil {
			// Check threshold - if rule has threshold > 1, track matches
			if rule.Threshold > 1 {
				thresholdReached := e.checkThreshold(rule)
				if !thresholdReached {
					// Threshold not reached yet, don't generate alert
					matched = true
					alertGenerated = false
					if e.perfTracker != nil {
						e.perfTracker.RecordRuleExecution(rule.Name, time.Since(ruleStart), matched, alertGenerated)
					}
					continue
				}
				// For threshold-based rules, skip deduplication since the threshold
				// itself provides rate limiting. The threshold tracker already ensures
				// we don't alert too frequently, and we want to alert each time the
				// threshold is reached (not just once per dedup window).
			} else {
				// Check deduplication only for non-threshold rules
				if e.isDuplicate(alert) {
					matched = true
					alertGenerated = false
					if e.perfTracker != nil {
						e.perfTracker.RecordRuleExecution(rule.Name, time.Since(ruleStart), matched, alertGenerated)
					}
					continue
				}
			}

			// Check rate limiting
			if e.isRateLimited(rule.Name) {
				matched = true
				alertGenerated = false
				if e.perfTracker != nil {
					e.perfTracker.RecordRuleExecution(rule.Name, time.Since(ruleStart), matched, alertGenerated)
				}
				continue
			}

			// Write the alert
			err = e.alertWriter.WriteAlert(alert)
			if err != nil {
				return alertCount, fmt.Errorf("error writing alert: %w", err)
			}

			alertCount++
			alertGenerated = true

			// Execute response actions
			if len(rule.Actions) > 0 {
				e.executeResponseActions(rule, record, alert)
			}
		}

		// Record per-rule metrics if performance tracker is set
		if e.perfTracker != nil {
			e.perfTracker.RecordRuleExecution(rule.Name, time.Since(ruleStart), matched, alertGenerated)
		}
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
		"total_rules":        len(e.config.Rules),
		"enabled_rules":      enabledRules,
		"threshold_rules":    thresholdRules,
		"recent_alerts":      len(e.recentAlerts),
		"dedup_window":       e.dedupWindow.String(),
		"rate_limit":         e.rateLimit,
		"tracked_thresholds": len(e.thresholdTrackers),
	}
}

// UpdateConfig updates the rules configuration in memory.
// This allows for runtime updates of rules without recreating the engine.
func (e *Engine) UpdateConfig(config *Config) error {
	// Compile all rules in the new config
	if err := CompileRules(config); err != nil {
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

// executeResponseActions executes all enabled response actions for a rule.
func (e *Engine) executeResponseActions(rule *Rule, record types.AuditRecord, alert *types.Alert) {
	for _, action := range rule.Actions {
		if !action.IsEnabled() {
			continue
		}

		e.actionStats.mu.Lock()
		e.actionStats.ActionsExecuted++
		e.actionStats.mu.Unlock()

		err := e.executeResponseAction(action, record, alert)
		if err != nil {
			e.actionStats.mu.Lock()
			e.actionStats.ActionsFailed++
			e.actionStats.mu.Unlock()
			// Log error but continue with other actions
			fmt.Printf("[RULES] Response action %s failed for rule %s: %v\n",
				action.Type, rule.Name, err)
		} else {
			e.actionStats.mu.Lock()
			e.actionStats.ActionsSuccess++
			e.actionStats.mu.Unlock()
		}
	}
}

// executeResponseAction executes a single response action.
func (e *Engine) executeResponseAction(action *ResponseAction, record types.AuditRecord, alert *types.Alert) error {
	switch action.Type {
	case "iptables_block":
		return e.executeIPTablesBlock(action, record, alert)
	case "iptables_reject":
		return e.executeIPTablesReject(action, record, alert)
	case "iptables_rate_limit":
		return e.executeIPTablesRateLimit(action, record, alert)
	case "iptables_log":
		return e.executeIPTablesLog(action, record, alert)
	default:
		return fmt.Errorf("unknown response action type: %s", action.Type)
	}
}

// executeIPTablesBlock blocks an IP using iptables.
func (e *Engine) executeIPTablesBlock(action *ResponseAction, record types.AuditRecord, alert *types.Alert) error {
	// Get firewall manager with proper locking
	manager := e.GetFirewallManager()
	if manager == nil {
		return fmt.Errorf("firewall manager not configured")
	}

	// Determine target IP
	target := "source"
	if t, ok := action.Config["target"].(string); ok {
		target = t
	}

	var ip string
	if target == "source" || target == "src" {
		ip = record.Src()
	} else {
		ip = record.Dst()
	}

	if ip == "" {
		return fmt.Errorf("could not determine IP to block from record")
	}

	// Get duration (handle string, int, and float64 from YAML parsing)
	duration := 30 * time.Minute
	if d, ok := action.Config["duration"].(string); ok {
		if parsed, err := time.ParseDuration(d); err == nil {
			duration = parsed
		}
	} else if d, ok := action.Config["duration"].(int); ok {
		// Assume minutes if just an integer
		duration = time.Duration(d) * time.Minute
	} else if d, ok := action.Config["duration"].(float64); ok {
		// YAML often parses numbers as float64
		duration = time.Duration(d) * time.Minute
	}

	// Build block config
	blockConfig := &firewall.BlockConfig{
		Target:   target,
		Duration: duration,
		Action:   "DROP",
		RuleName: alert.RuleName,
		Reason:   fmt.Sprintf("%s - %s", alert.Description, alert.Severity),
	}

	err := manager.BlockIP(ip, blockConfig)
	if err != nil {
		return err
	}

	e.actionStats.mu.Lock()
	e.actionStats.IPsBlocked++
	e.actionStats.mu.Unlock()

	return nil
}

// executeIPTablesReject rejects traffic with an ICMP response.
func (e *Engine) executeIPTablesReject(action *ResponseAction, record types.AuditRecord, alert *types.Alert) error {
	// Get firewall manager with proper locking
	manager := e.GetFirewallManager()
	if manager == nil {
		return fmt.Errorf("firewall manager not configured")
	}

	// Same as block but with REJECT action
	target := "source"
	if t, ok := action.Config["target"].(string); ok {
		target = t
	}

	var ip string
	if target == "source" || target == "src" {
		ip = record.Src()
	} else {
		ip = record.Dst()
	}

	if ip == "" {
		return fmt.Errorf("could not determine IP to reject from record")
	}

	// Get duration (handle string, int, and float64 from YAML parsing)
	duration := 30 * time.Minute
	if d, ok := action.Config["duration"].(string); ok {
		if parsed, err := time.ParseDuration(d); err == nil {
			duration = parsed
		}
	} else if d, ok := action.Config["duration"].(int); ok {
		duration = time.Duration(d) * time.Minute
	} else if d, ok := action.Config["duration"].(float64); ok {
		duration = time.Duration(d) * time.Minute
	}

	blockConfig := &firewall.BlockConfig{
		Target:   target,
		Duration: duration,
		Action:   "REJECT",
		RuleName: alert.RuleName,
		Reason:   fmt.Sprintf("%s - %s", alert.Description, alert.Severity),
	}

	return manager.BlockIP(ip, blockConfig)
}

// executeIPTablesRateLimit rate-limits traffic from/to an IP.
func (e *Engine) executeIPTablesRateLimit(action *ResponseAction, record types.AuditRecord, alert *types.Alert) error {
	// Rate limiting requires hashlimit module - placeholder for now
	fmt.Printf("[RULES] Rate limit action not yet fully implemented for rule %s\n", alert.RuleName)
	return nil
}

// executeIPTablesLog logs matching traffic via iptables.
func (e *Engine) executeIPTablesLog(action *ResponseAction, record types.AuditRecord, alert *types.Alert) error {
	// Logging is already done via alerts - this is for iptables-level logging
	prefix := "NETCAP: "
	if p, ok := action.Config["prefix"].(string); ok {
		prefix = p
	}

	fmt.Printf("[RULES] LOG: %s%s src=%s dst=%s\n",
		prefix, alert.RuleName, record.Src(), record.Dst())

	return nil
}

// GetActionStats returns response action statistics.
func (e *Engine) GetActionStats() map[string]uint64 {
	e.actionStats.mu.Lock()
	defer e.actionStats.mu.Unlock()

	return map[string]uint64{
		"actions_executed": e.actionStats.ActionsExecuted,
		"actions_success":  e.actionStats.ActionsSuccess,
		"actions_failed":   e.actionStats.ActionsFailed,
		"ips_blocked":      e.actionStats.IPsBlocked,
	}
}
