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

package secret

import (
	"fmt"
	"sync"
	"time"
)

// BruteforceConfig holds configuration for bruteforce detection
type BruteforceConfig struct {
	// FailureThreshold is the number of failed attempts before alerting
	FailureThreshold int `yaml:"failure_threshold"`
	// MeasurementInterval is the time window for counting failures
	MeasurementInterval time.Duration `yaml:"measurement_interval"`
	// PerSourceTracking tracks failures per source IP
	PerSourceTracking bool `yaml:"per_source_tracking"`
	// PerServiceTracking tracks failures per service type
	PerServiceTracking bool `yaml:"per_service_tracking"`
	// Enabled controls whether bruteforce detection is active
	Enabled bool `yaml:"enabled"`
}

// DefaultBruteforceConfig returns default bruteforce detection settings
// Similar to Zeek's FTP/SSH bruteforce detection defaults
func DefaultBruteforceConfig() *BruteforceConfig {
	return &BruteforceConfig{
		FailureThreshold:    20,               // Like Zeek's FTP bruteforce_threshold
		MeasurementInterval: 15 * time.Minute, // Like Zeek's bruteforce_measurement_interval
		PerSourceTracking:   true,
		PerServiceTracking:  true,
		Enabled:             true,
	}
}

// BruteforceAlert represents a detected bruteforce attack
type BruteforceAlert struct {
	Timestamp      time.Time
	SourceIP       string
	Service        string
	FailedAttempts int
	TargetServers  []string // Unique servers targeted
	Duration       time.Duration
	FirstAttempt   time.Time
	LastAttempt    time.Time
}

// String returns a human-readable description of the alert
func (a *BruteforceAlert) String() string {
	plural := ""
	if len(a.TargetServers) > 1 {
		plural = "s"
	}
	return fmt.Sprintf("%s: %s had %d failed logins on %d server%s in %v",
		a.Timestamp.Format(time.RFC3339),
		a.SourceIP,
		a.FailedAttempts,
		len(a.TargetServers),
		plural,
		a.Duration)
}

// failedAttempt tracks a single failed authentication attempt
type failedAttempt struct {
	timestamp time.Time
	targetIP  string
	service   string
	username  string
}

// BruteforceDetector tracks failed authentication attempts and detects bruteforce attacks
// Similar to Zeek's SumStats-based approach
type BruteforceDetector struct {
	mu     sync.RWMutex
	config *BruteforceConfig

	// Track failures per source IP
	sourceFailures map[string][]failedAttempt

	// Track failures per (source, service) pair
	serviceFailures map[string][]failedAttempt

	// Alerts generated
	alerts []BruteforceAlert

	// Alert callback
	alertCallback func(BruteforceAlert)

	// Cleanup ticker
	cleanupTicker *time.Ticker
	stopChan      chan struct{}
}

// NewBruteforceDetector creates a new bruteforce detection instance
func NewBruteforceDetector(config *BruteforceConfig) *BruteforceDetector {
	if config == nil {
		config = DefaultBruteforceConfig()
	}

	d := &BruteforceDetector{
		config:          config,
		sourceFailures:  make(map[string][]failedAttempt),
		serviceFailures: make(map[string][]failedAttempt),
		alerts:          make([]BruteforceAlert, 0),
		stopChan:        make(chan struct{}),
	}

	// Start periodic cleanup
	d.cleanupTicker = time.NewTicker(config.MeasurementInterval / 2)
	go d.cleanupLoop()

	return d
}

// SetAlertCallback sets the function to call when a bruteforce alert is generated
func (d *BruteforceDetector) SetAlertCallback(cb func(BruteforceAlert)) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.alertCallback = cb
}

// RecordFailure records a failed authentication attempt
// This should be called whenever AuthSuccessSet is true and AuthSuccess is false
func (d *BruteforceDetector) RecordFailure(sourceIP, targetIP, service, username string, ts time.Time) {
	if !d.config.Enabled {
		return
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	attempt := failedAttempt{
		timestamp: ts,
		targetIP:  targetIP,
		service:   service,
		username:  username,
	}

	// Track per source IP
	if d.config.PerSourceTracking {
		d.sourceFailures[sourceIP] = append(d.sourceFailures[sourceIP], attempt)
		d.checkThreshold(sourceIP, "", d.sourceFailures[sourceIP])
	}

	// Track per (source, service) pair
	if d.config.PerServiceTracking {
		key := fmt.Sprintf("%s:%s", sourceIP, service)
		d.serviceFailures[key] = append(d.serviceFailures[key], attempt)
		d.checkThreshold(sourceIP, service, d.serviceFailures[key])
	}
}

// RecordSuccess records a successful authentication (can be used to track password guessers who succeeded)
func (d *BruteforceDetector) RecordSuccess(sourceIP, targetIP, service, username string, ts time.Time) {
	if !d.config.Enabled {
		return
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	// Check if this source was flagged as a bruteforcer
	if failures, ok := d.sourceFailures[sourceIP]; ok && len(failures) >= d.config.FailureThreshold {
		// This could generate a "Login_By_Password_Guesser" alert like Zeek
		// For now, we just log the fact
		credLog.Info(fmt.Sprintf("Password guesser %s succeeded: user=%s service=%s", sourceIP, username, service))
	}
}

// checkThreshold checks if the failure threshold has been crossed
func (d *BruteforceDetector) checkThreshold(sourceIP, service string, attempts []failedAttempt) {
	// Prune old attempts
	cutoff := time.Now().Add(-d.config.MeasurementInterval)
	validAttempts := make([]failedAttempt, 0, len(attempts))
	for _, a := range attempts {
		if a.timestamp.After(cutoff) {
			validAttempts = append(validAttempts, a)
		}
	}

	if len(validAttempts) < d.config.FailureThreshold {
		return
	}

	// Check if we already generated an alert for this source recently
	for _, alert := range d.alerts {
		if alert.SourceIP == sourceIP && (service == "" || alert.Service == service) {
			if alert.Timestamp.After(cutoff) {
				// Already alerted recently
				return
			}
		}
	}

	// Gather unique target servers
	targetSet := make(map[string]struct{})
	for _, a := range validAttempts {
		targetSet[a.targetIP] = struct{}{}
	}
	targets := make([]string, 0, len(targetSet))
	for t := range targetSet {
		targets = append(targets, t)
	}

	// Calculate duration
	var firstAttempt, lastAttempt time.Time
	for i, a := range validAttempts {
		if i == 0 || a.timestamp.Before(firstAttempt) {
			firstAttempt = a.timestamp
		}
		if i == 0 || a.timestamp.After(lastAttempt) {
			lastAttempt = a.timestamp
		}
	}

	alert := BruteforceAlert{
		Timestamp:      time.Now(),
		SourceIP:       sourceIP,
		Service:        service,
		FailedAttempts: len(validAttempts),
		TargetServers:  targets,
		Duration:       lastAttempt.Sub(firstAttempt),
		FirstAttempt:   firstAttempt,
		LastAttempt:    lastAttempt,
	}

	d.alerts = append(d.alerts, alert)

	// Call callback if set
	if d.alertCallback != nil {
		go d.alertCallback(alert)
	}

	// Log the alert
	credLog.Warn(fmt.Sprintf("Bruteforce detected: %s", alert.String()))

	// Clear the attempts to prevent repeated alerts
	if service != "" {
		key := fmt.Sprintf("%s:%s", sourceIP, service)
		d.serviceFailures[key] = nil
	} else {
		d.sourceFailures[sourceIP] = nil
	}
}

// cleanupLoop periodically removes old attempts
func (d *BruteforceDetector) cleanupLoop() {
	for {
		select {
		case <-d.cleanupTicker.C:
			d.cleanup()
		case <-d.stopChan:
			return
		}
	}
}

// cleanup removes attempts older than the measurement interval
func (d *BruteforceDetector) cleanup() {
	d.mu.Lock()
	defer d.mu.Unlock()

	cutoff := time.Now().Add(-d.config.MeasurementInterval)

	// Cleanup source failures
	for source, attempts := range d.sourceFailures {
		validAttempts := make([]failedAttempt, 0, len(attempts))
		for _, a := range attempts {
			if a.timestamp.After(cutoff) {
				validAttempts = append(validAttempts, a)
			}
		}
		if len(validAttempts) == 0 {
			delete(d.sourceFailures, source)
		} else {
			d.sourceFailures[source] = validAttempts
		}
	}

	// Cleanup service failures
	for key, attempts := range d.serviceFailures {
		validAttempts := make([]failedAttempt, 0, len(attempts))
		for _, a := range attempts {
			if a.timestamp.After(cutoff) {
				validAttempts = append(validAttempts, a)
			}
		}
		if len(validAttempts) == 0 {
			delete(d.serviceFailures, key)
		} else {
			d.serviceFailures[key] = validAttempts
		}
	}

	// Cleanup old alerts (keep for 2x measurement interval)
	alertCutoff := time.Now().Add(-2 * d.config.MeasurementInterval)
	validAlerts := make([]BruteforceAlert, 0, len(d.alerts))
	for _, a := range d.alerts {
		if a.Timestamp.After(alertCutoff) {
			validAlerts = append(validAlerts, a)
		}
	}
	d.alerts = validAlerts
}

// Stop stops the bruteforce detector and cleans up resources
func (d *BruteforceDetector) Stop() {
	d.cleanupTicker.Stop()
	close(d.stopChan)
}

// GetAlerts returns all currently tracked alerts
func (d *BruteforceDetector) GetAlerts() []BruteforceAlert {
	d.mu.RLock()
	defer d.mu.RUnlock()

	alerts := make([]BruteforceAlert, len(d.alerts))
	copy(alerts, d.alerts)
	return alerts
}

// GetStats returns statistics about the detector
func (d *BruteforceDetector) GetStats() map[string]any {
	d.mu.RLock()
	defer d.mu.RUnlock()

	totalSourceFailures := 0
	for _, attempts := range d.sourceFailures {
		totalSourceFailures += len(attempts)
	}

	totalServiceFailures := 0
	for _, attempts := range d.serviceFailures {
		totalServiceFailures += len(attempts)
	}

	return map[string]any{
		"tracked_sources":        len(d.sourceFailures),
		"tracked_service_pairs":  len(d.serviceFailures),
		"total_source_failures":  totalSourceFailures,
		"total_service_failures": totalServiceFailures,
		"total_alerts":           len(d.alerts),
		"failure_threshold":      d.config.FailureThreshold,
		"measurement_interval":   d.config.MeasurementInterval.String(),
	}
}

// Global bruteforce detector instance
var (
	bruteforceDetector     *BruteforceDetector
	bruteforceDetectorMu   sync.RWMutex
	bruteforceDetectorInit bool
)

// GetBruteforceDetector returns the global bruteforce detector instance
func GetBruteforceDetector() *BruteforceDetector {
	bruteforceDetectorMu.RLock()
	if bruteforceDetectorInit {
		d := bruteforceDetector
		bruteforceDetectorMu.RUnlock()
		return d
	}
	bruteforceDetectorMu.RUnlock()

	// Upgrade to write lock for initialization
	bruteforceDetectorMu.Lock()
	defer bruteforceDetectorMu.Unlock()

	// Double-check after acquiring write lock
	if !bruteforceDetectorInit {
		bruteforceDetector = NewBruteforceDetector(nil)
		bruteforceDetectorInit = true
	}
	return bruteforceDetector
}

// InitBruteforceDetector initializes the global bruteforce detector with custom config
// This should be called before any calls to GetBruteforceDetector for proper configuration
func InitBruteforceDetector(config *BruteforceConfig) {
	bruteforceDetectorMu.Lock()
	defer bruteforceDetectorMu.Unlock()

	if bruteforceDetector != nil {
		bruteforceDetector.Stop()
	}
	bruteforceDetector = NewBruteforceDetector(config)
	bruteforceDetectorInit = true
}
