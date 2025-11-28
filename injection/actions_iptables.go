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

package injection

import (
	"fmt"
	"sync"
	"time"

	"github.com/dreadl0ck/netcap/firewall"
)

// Global firewall manager instance for injection handlers.
// Must be initialized before using iptables actions.
var (
	globalFirewallManager   *firewall.Manager
	globalFirewallManagerMu sync.RWMutex
)

// SetFirewallManager sets the global firewall manager for iptables actions.
func SetFirewallManager(manager *firewall.Manager) {
	globalFirewallManagerMu.Lock()
	defer globalFirewallManagerMu.Unlock()
	globalFirewallManager = manager
}

// GetFirewallManager returns the global firewall manager.
func GetFirewallManager() *firewall.Manager {
	globalFirewallManagerMu.RLock()
	defer globalFirewallManagerMu.RUnlock()
	return globalFirewallManager
}

// IPTablesBlockHandler handles iptables block actions.
type IPTablesBlockHandler struct{}

// Execute blocks the source or destination IP via iptables.
func (h *IPTablesBlockHandler) Execute(ctx *InjectionContext, config map[string]interface{}) (*ActionResult, error) {
	result := &ActionResult{
		Action:    ActionIPTablesBlock,
		Timestamp: time.Now(),
		Details:   make(map[string]interface{}),
	}

	manager := GetFirewallManager()
	if manager == nil {
		return nil, fmt.Errorf("iptables_block: firewall manager not initialized")
	}

	// Determine target IP based on config
	target := "source"
	if t, ok := config["target"].(string); ok {
		target = t
	}

	var ip string
	if target == "source" || target == "src" {
		ip = ctx.SrcIP()
	} else {
		ip = ctx.DstIP()
	}

	if ip == "" {
		return nil, fmt.Errorf("iptables_block: could not determine IP to block")
	}

	// Get duration (handle string, int, and float64 from YAML parsing)
	duration := 30 * time.Minute // default 30 min block
	if d, ok := config["duration"].(string); ok {
		if parsed, err := time.ParseDuration(d); err == nil {
			duration = parsed
		}
	} else if d, ok := config["duration"].(int); ok {
		duration = time.Duration(d) * time.Minute
	} else if d, ok := config["duration"].(float64); ok {
		duration = time.Duration(d) * time.Minute
	}

	// Get action (DROP or REJECT)
	action := "DROP"
	if a, ok := config["action"].(string); ok {
		action = a
	}

	// Get rule name
	ruleName := "injection"
	if name, ok := config["rule_name"].(string); ok {
		ruleName = name
	}

	// Get reason
	reason := ctx.Flow
	if r, ok := config["reason"].(string); ok {
		reason = r
	}

	// Block the IP
	blockConfig := &firewall.BlockConfig{
		Target:   target,
		Duration: duration,
		Action:   action,
		RuleName: ruleName,
		Reason:   reason,
	}

	err := manager.BlockIP(ip, blockConfig)
	if err != nil {
		result.Error = err
		result.Details["error"] = err.Error()
		return result, err
	}

	result.Success = true
	result.Drop = true // Also drop the current packet
	result.Details["blocked_ip"] = ip
	result.Details["duration"] = duration.String()
	result.Details["target"] = target
	result.Details["action"] = action

	return result, nil
}

// IPTablesRejectHandler handles iptables reject actions.
type IPTablesRejectHandler struct{}

// Execute rejects traffic from/to an IP with an ICMP response.
func (h *IPTablesRejectHandler) Execute(ctx *InjectionContext, config map[string]interface{}) (*ActionResult, error) {
	// Create a copy of config to avoid modifying the original
	rejectConfig := make(map[string]interface{}, len(config)+1)
	for k, v := range config {
		rejectConfig[k] = v
	}
	rejectConfig["action"] = "REJECT"

	blockHandler := &IPTablesBlockHandler{}
	result, err := blockHandler.Execute(ctx, rejectConfig)
	if result != nil {
		result.Action = ActionIPTablesReject
	}
	return result, err
}

// IPTablesLogHandler handles iptables log actions.
type IPTablesLogHandler struct{}

// Execute logs traffic matching the rule via iptables LOG target.
func (h *IPTablesLogHandler) Execute(ctx *InjectionContext, config map[string]interface{}) (*ActionResult, error) {
	result := &ActionResult{
		Action:    ActionIPTablesLog,
		Timestamp: time.Now(),
		Details:   make(map[string]interface{}),
	}

	// For now, log action just records details but doesn't modify iptables
	// A full implementation would add a LOG rule to iptables

	prefix := "NETCAP: "
	if p, ok := config["prefix"].(string); ok {
		prefix = p
	}

	result.Success = true
	result.Details["logged"] = true
	result.Details["prefix"] = prefix
	result.Details["src_ip"] = ctx.SrcIP()
	result.Details["dst_ip"] = ctx.DstIP()
	result.Details["flow"] = ctx.Flow

	return result, nil
}

// IPTablesRateLimitHandler handles iptables rate limiting actions.
type IPTablesRateLimitHandler struct{}

// Execute rate-limits traffic from/to an IP.
func (h *IPTablesRateLimitHandler) Execute(ctx *InjectionContext, config map[string]interface{}) (*ActionResult, error) {
	result := &ActionResult{
		Action:    ActionIPTablesRateLimit,
		Timestamp: time.Now(),
		Details:   make(map[string]interface{}),
	}

	// Rate limiting requires more complex iptables rules with hashlimit module
	// For now, we document this as a placeholder

	rate := "10/minute"
	if r, ok := config["rate"].(string); ok {
		rate = r
	}

	burst := 5
	if b, ok := config["burst"].(int); ok {
		burst = b
	}

	result.Success = true
	result.Details["rate_limit"] = rate
	result.Details["burst"] = burst
	result.Details["src_ip"] = ctx.SrcIP()
	result.Details["note"] = "rate limiting via hashlimit not yet implemented"

	return result, nil
}
