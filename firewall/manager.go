//go:build linux

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

// Package firewall provides iptables integration for automated response actions.
// It wraps the coreos/go-iptables library to provide a safe, managed interface
// for creating and removing firewall rules in response to security detections.
package firewall

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/coreos/go-iptables/iptables"
)

// Type aliases for backward compatibility
const (
	DefaultChainName       = DefaultChainNameConst
	DefaultCleanupInterval = DefaultCleanupIntervalConst
	DefaultBlockDuration   = DefaultBlockDurationConfig
)

// Manager handles iptables rule management with automatic cleanup.
type Manager struct {
	ipt4 *iptables.IPTables // IPv4 iptables
	ipt6 *iptables.IPTables // IPv6 ip6tables

	chainName string

	// Track active blocks for deduplication and expiration
	activeBlocks map[string]*BlockEntry
	mu           sync.RWMutex

	// Whitelist of IPs/CIDRs that should never be blocked
	whitelist map[string]bool

	// Cleanup ticker
	cleanupTicker *time.Ticker
	shutdown      chan struct{}
	wg            sync.WaitGroup

	// Configuration
	config *ManagerConfig

	// Statistics
	stats *internalStats
}

// internalStats wraps Stats with a mutex for thread-safe access.
type internalStats struct {
	mu sync.Mutex
	Stats
}

// NewManager creates a new firewall manager.
func NewManager(config *ManagerConfig) (*Manager, error) {
	if config == nil {
		config = DefaultManagerConfig()
	}

	m := &Manager{
		chainName:    config.ChainName,
		activeBlocks: make(map[string]*BlockEntry),
		whitelist:    make(map[string]bool),
		shutdown:     make(chan struct{}),
		config:       config,
		stats:        &internalStats{},
	}

	// Initialize whitelist
	for _, w := range config.Whitelist {
		m.whitelist[w] = true
	}

	// Initialize IPv4 iptables
	if config.EnableIPv4 {
		ipt4, err := iptables.New(iptables.IPFamily(iptables.ProtocolIPv4))
		if err != nil {
			return nil, fmt.Errorf("failed to initialize iptables (IPv4): %w", err)
		}
		m.ipt4 = ipt4
	}

	// Initialize IPv6 ip6tables
	if config.EnableIPv6 {
		ipt6, err := iptables.New(iptables.IPFamily(iptables.ProtocolIPv6))
		if err != nil {
			// IPv6 might not be available, log but continue
			if config.Verbose {
				fmt.Printf("Warning: failed to initialize ip6tables (IPv6): %v\n", err)
			}
		} else {
			m.ipt6 = ipt6
		}
	}

	// Setup custom chains
	if err := m.setupChains(); err != nil {
		return nil, fmt.Errorf("failed to setup chains: %w", err)
	}

	// Start cleanup goroutine
	m.cleanupTicker = time.NewTicker(config.CleanupInterval)
	m.wg.Add(1)
	go m.cleanupLoop()

	return m, nil
}

// setupChains creates the custom NETCAP chain and adds jump rules.
func (m *Manager) setupChains() error {
	if m.config.DryRun {
		return nil
	}

	// Setup IPv4 chain
	if m.ipt4 != nil {
		if err := m.setupChain(m.ipt4); err != nil {
			return fmt.Errorf("IPv4: %w", err)
		}
	}

	// Setup IPv6 chain
	if m.ipt6 != nil {
		if err := m.setupChain(m.ipt6); err != nil {
			return fmt.Errorf("IPv6: %w", err)
		}
	}

	return nil
}

// setupChain creates a custom chain for the given iptables instance.
func (m *Manager) setupChain(ipt *iptables.IPTables) error {
	// Check if chain exists
	chains, err := ipt.ListChains("filter")
	if err != nil {
		return fmt.Errorf("failed to list chains: %w", err)
	}

	chainExists := false
	for _, chain := range chains {
		if chain == m.chainName {
			chainExists = true
			break
		}
	}

	// Create chain if it doesn't exist
	if !chainExists {
		if err := ipt.NewChain("filter", m.chainName); err != nil {
			return fmt.Errorf("failed to create chain %s: %w", m.chainName, err)
		}
	}

	// Add jump rules from INPUT, FORWARD, OUTPUT if not already present
	for _, parentChain := range []string{"INPUT", "FORWARD", "OUTPUT"} {
		jumpRule := []string{"-j", m.chainName}

		exists, err := ipt.Exists("filter", parentChain, jumpRule...)
		if err != nil {
			return fmt.Errorf("failed to check jump rule in %s: %w", parentChain, err)
		}

		if !exists {
			// Insert at the beginning
			if err := ipt.Insert("filter", parentChain, 1, jumpRule...); err != nil {
				return fmt.Errorf("failed to add jump rule to %s: %w", parentChain, err)
			}
		}
	}

	return nil
}

// BlockIP adds an iptables rule to block an IP address.
func (m *Manager) BlockIP(ip string, config *BlockConfig) error {
	// Validate IP
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return fmt.Errorf("invalid IP address: %s", ip)
	}

	// Check whitelist
	if m.isWhitelisted(ip) {
		m.stats.mu.Lock()
		m.stats.WhitelistSkip++
		m.stats.mu.Unlock()
		return nil
	}

	// Check for duplicate
	m.mu.Lock()
	if _, exists := m.activeBlocks[ip]; exists {
		m.mu.Unlock()
		m.stats.mu.Lock()
		m.stats.DuplicatesSkip++
		m.stats.mu.Unlock()
		return nil
	}

	// Create block entry
	entry := m.createBlockEntry(ip, "", config)
	m.activeBlocks[ip] = entry
	m.mu.Unlock()

	// Add iptables rule
	if err := m.addBlockRule(ip, config, parsedIP.To4() != nil); err != nil {
		m.mu.Lock()
		delete(m.activeBlocks, ip)
		m.mu.Unlock()
		m.stats.mu.Lock()
		m.stats.Errors++
		m.stats.mu.Unlock()
		return err
	}

	m.stats.mu.Lock()
	m.stats.BlocksCreated++
	m.stats.mu.Unlock()

	if m.config.Verbose {
		fmt.Printf("[FIREWALL] Blocked IP %s (rule: %s, expires: %v)\n",
			ip, config.RuleName, entry.ExpiresAt)
	}

	return nil
}

// BlockCIDR adds an iptables rule to block a CIDR range.
func (m *Manager) BlockCIDR(cidr string, config *BlockConfig) error {
	// Validate CIDR
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return fmt.Errorf("invalid CIDR: %s", cidr)
	}

	// Check whitelist
	if m.isWhitelisted(cidr) {
		m.stats.mu.Lock()
		m.stats.WhitelistSkip++
		m.stats.mu.Unlock()
		return nil
	}

	// Check for duplicate
	m.mu.Lock()
	if _, exists := m.activeBlocks[cidr]; exists {
		m.mu.Unlock()
		m.stats.mu.Lock()
		m.stats.DuplicatesSkip++
		m.stats.mu.Unlock()
		return nil
	}

	// Create block entry
	entry := m.createBlockEntry("", cidr, config)
	m.activeBlocks[cidr] = entry
	m.mu.Unlock()

	// Determine if IPv4 or IPv6
	isIPv4 := network.IP.To4() != nil

	// Add iptables rule
	if err := m.addBlockRule(cidr, config, isIPv4); err != nil {
		m.mu.Lock()
		delete(m.activeBlocks, cidr)
		m.mu.Unlock()
		m.stats.mu.Lock()
		m.stats.Errors++
		m.stats.mu.Unlock()
		return err
	}

	m.stats.mu.Lock()
	m.stats.BlocksCreated++
	m.stats.mu.Unlock()

	if m.config.Verbose {
		fmt.Printf("[FIREWALL] Blocked CIDR %s (rule: %s, expires: %v)\n",
			cidr, config.RuleName, entry.ExpiresAt)
	}

	return nil
}

// createBlockEntry creates a new block entry.
func (m *Manager) createBlockEntry(ip, cidr string, config *BlockConfig) *BlockEntry {
	entry := &BlockEntry{
		IP:        ip,
		CIDR:      cidr,
		CreatedAt: time.Now(),
		RuleName:  config.RuleName,
		Reason:    config.Reason,
		Chain:     config.Chain,
		Target:    config.Target,
		Action:    config.Action,
	}

	duration := config.Duration
	if duration == 0 {
		duration = m.config.DefaultDuration
	}

	if duration > 0 {
		entry.ExpiresAt = time.Now().Add(duration)
	}

	return entry
}

// addBlockRule adds an iptables rule for blocking.
func (m *Manager) addBlockRule(target string, config *BlockConfig, isIPv4 bool) error {
	if m.config.DryRun {
		fmt.Printf("[FIREWALL DRY-RUN] Would block %s (target: %s, action: %s)\n",
			target, config.Target, config.Action)
		return nil
	}

	var ipt *iptables.IPTables
	if isIPv4 {
		ipt = m.ipt4
	} else {
		ipt = m.ipt6
	}

	if ipt == nil {
		return fmt.Errorf("iptables not available for this protocol")
	}

	// Build rule specification
	ruleSpec := m.buildRuleSpec(target, config)

	// Check if rule already exists
	exists, err := ipt.Exists("filter", m.chainName, ruleSpec...)
	if err != nil {
		return fmt.Errorf("failed to check existing rule: %w", err)
	}

	if exists {
		return nil // Rule already exists
	}

	// Append rule
	if err := ipt.Append("filter", m.chainName, ruleSpec...); err != nil {
		return fmt.Errorf("failed to add rule: %w", err)
	}

	return nil
}

// buildRuleSpec builds the iptables rule specification.
func (m *Manager) buildRuleSpec(target string, config *BlockConfig) []string {
	var spec []string

	// Source or destination
	if config.Target == "source" || config.Target == "src" {
		spec = append(spec, "-s", target)
	} else {
		spec = append(spec, "-d", target)
	}

	// Action (DROP or REJECT)
	action := config.Action
	if action == "" {
		action = "DROP"
	}
	spec = append(spec, "-j", action)

	// Comment (iptables has a 256 character limit for comments)
	comment := fmt.Sprintf("NETCAP: %s", config.RuleName)
	if config.Reason != "" {
		comment = fmt.Sprintf("NETCAP: %s - %s", config.RuleName, config.Reason)
	}
	// Truncate comment if too long (iptables limit is 256 chars)
	const maxCommentLen = 255
	if len(comment) > maxCommentLen {
		comment = comment[:maxCommentLen-3] + "..."
	}
	spec = append(spec, "-m", "comment", "--comment", comment)

	return spec
}

// UnblockIP removes a block for an IP address.
func (m *Manager) UnblockIP(ip string) error {
	m.mu.Lock()
	entry, exists := m.activeBlocks[ip]
	if !exists {
		m.mu.Unlock()
		return nil
	}
	delete(m.activeBlocks, ip)
	m.mu.Unlock()

	// Remove iptables rule
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return fmt.Errorf("invalid IP address: %s", ip)
	}

	if err := m.removeBlockRule(ip, entry, parsedIP.To4() != nil); err != nil {
		return err
	}

	m.stats.mu.Lock()
	m.stats.BlocksRemoved++
	m.stats.mu.Unlock()

	if m.config.Verbose {
		fmt.Printf("[FIREWALL] Unblocked IP %s\n", ip)
	}

	return nil
}

// UnblockCIDR removes a block for a CIDR range.
func (m *Manager) UnblockCIDR(cidr string) error {
	m.mu.Lock()
	entry, exists := m.activeBlocks[cidr]
	if !exists {
		m.mu.Unlock()
		return nil
	}
	delete(m.activeBlocks, cidr)
	m.mu.Unlock()

	// Determine if IPv4 or IPv6
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return fmt.Errorf("invalid CIDR: %s", cidr)
	}

	if err := m.removeBlockRule(cidr, entry, network.IP.To4() != nil); err != nil {
		return err
	}

	m.stats.mu.Lock()
	m.stats.BlocksRemoved++
	m.stats.mu.Unlock()

	if m.config.Verbose {
		fmt.Printf("[FIREWALL] Unblocked CIDR %s\n", cidr)
	}

	return nil
}

// removeBlockRule removes an iptables rule.
func (m *Manager) removeBlockRule(target string, entry *BlockEntry, isIPv4 bool) error {
	if m.config.DryRun {
		fmt.Printf("[FIREWALL DRY-RUN] Would unblock %s\n", target)
		return nil
	}

	var ipt *iptables.IPTables
	if isIPv4 {
		ipt = m.ipt4
	} else {
		ipt = m.ipt6
	}

	if ipt == nil {
		return nil
	}

	// Build rule spec from entry
	config := &BlockConfig{
		Target:   entry.Target,
		Action:   entry.Action,
		RuleName: entry.RuleName,
		Reason:   entry.Reason,
	}
	ruleSpec := m.buildRuleSpec(target, config)

	// Delete rule
	if err := ipt.Delete("filter", m.chainName, ruleSpec...); err != nil {
		// Rule might not exist, log but don't error
		if m.config.Verbose {
			fmt.Printf("[FIREWALL] Warning: failed to remove rule for %s: %v\n", target, err)
		}
	}

	return nil
}

// IsBlocked checks if an IP is currently blocked.
func (m *Manager) IsBlocked(ip string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	entry, exists := m.activeBlocks[ip]
	if !exists {
		return false
	}

	return !entry.IsExpired()
}

// GetActiveBlocks returns all currently active blocks.
func (m *Manager) GetActiveBlocks() []*BlockEntry {
	m.mu.RLock()
	defer m.mu.RUnlock()

	blocks := make([]*BlockEntry, 0, len(m.activeBlocks))
	for _, entry := range m.activeBlocks {
		if !entry.IsExpired() {
			blocks = append(blocks, entry)
		}
	}

	return blocks
}

// GetStats returns current statistics.
func (m *Manager) GetStats() map[string]uint64 {
	// Lock both mutexes to get consistent stats
	m.mu.RLock()
	activeCount := uint64(len(m.activeBlocks))
	m.mu.RUnlock()

	m.stats.mu.Lock()
	defer m.stats.mu.Unlock()

	return map[string]uint64{
		"blocks_created":  m.stats.BlocksCreated,
		"blocks_removed":  m.stats.BlocksRemoved,
		"blocks_expired":  m.stats.BlocksExpired,
		"duplicates_skip": m.stats.DuplicatesSkip,
		"whitelist_skip":  m.stats.WhitelistSkip,
		"errors":          m.stats.Errors,
		"active_blocks":   activeCount,
	}
}

// isWhitelisted checks if an IP or CIDR is in the whitelist.
func (m *Manager) isWhitelisted(target string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Direct match
	if m.whitelist[target] {
		return true
	}

	// Check if target IP is within any whitelisted CIDR
	targetIP := net.ParseIP(target)
	if targetIP != nil {
		for w := range m.whitelist {
			_, network, err := net.ParseCIDR(w)
			if err == nil && network.Contains(targetIP) {
				return true
			}
		}
	}

	return false
}

// AddToWhitelist adds an IP or CIDR to the whitelist.
func (m *Manager) AddToWhitelist(target string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.whitelist[target] = true
}

// RemoveFromWhitelist removes an IP or CIDR from the whitelist.
func (m *Manager) RemoveFromWhitelist(target string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.whitelist, target)
}

// cleanupLoop periodically removes expired blocks.
func (m *Manager) cleanupLoop() {
	defer m.wg.Done()

	for {
		select {
		case <-m.shutdown:
			return
		case <-m.cleanupTicker.C:
			m.cleanupExpired()
		}
	}
}

// cleanupExpired removes all expired blocks.
func (m *Manager) cleanupExpired() {
	m.mu.Lock()
	expired := make([]string, 0)
	for key, entry := range m.activeBlocks {
		if entry.IsExpired() {
			expired = append(expired, key)
		}
	}
	m.mu.Unlock()

	for _, key := range expired {
		var err error
		if net.ParseIP(key) != nil {
			err = m.UnblockIP(key)
		} else {
			err = m.UnblockCIDR(key)
		}

		if err != nil && m.config.Verbose {
			fmt.Printf("[FIREWALL] Error removing expired block %s: %v\n", key, err)
		}
		// Note: Don't increment BlocksExpired here since UnblockIP/UnblockCIDR
		// already increments BlocksRemoved. The caller can check if a block
		// was removed due to expiration by checking timestamps.
	}

	// Track how many were cleaned up this cycle
	if len(expired) > 0 {
		m.stats.mu.Lock()
		m.stats.BlocksExpired += uint64(len(expired))
		m.stats.mu.Unlock()
	}
}

// Flush removes all rules from the NETCAP chain.
func (m *Manager) Flush() error {
	if m.config.DryRun {
		fmt.Printf("[FIREWALL DRY-RUN] Would flush all NETCAP rules\n")
		return nil
	}

	// Flush IPv4 chain
	if m.ipt4 != nil {
		if err := m.ipt4.ClearChain("filter", m.chainName); err != nil {
			return fmt.Errorf("failed to flush IPv4 chain: %w", err)
		}
	}

	// Flush IPv6 chain
	if m.ipt6 != nil {
		if err := m.ipt6.ClearChain("filter", m.chainName); err != nil {
			return fmt.Errorf("failed to flush IPv6 chain: %w", err)
		}
	}

	// Clear active blocks
	m.mu.Lock()
	m.activeBlocks = make(map[string]*BlockEntry)
	m.mu.Unlock()

	if m.config.Verbose {
		fmt.Printf("[FIREWALL] Flushed all NETCAP rules\n")
	}

	return nil
}

// Close cleans up all netcap-managed iptables rules and stops the cleanup goroutine.
func (m *Manager) Close() error {
	// Stop cleanup goroutine
	close(m.shutdown)
	m.cleanupTicker.Stop()
	m.wg.Wait()

	// Flush all rules
	if err := m.Flush(); err != nil {
		return err
	}

	// Remove jump rules and custom chain
	if err := m.removeChains(); err != nil {
		return err
	}

	if m.config.Verbose {
		fmt.Printf("[FIREWALL] Closed and cleaned up\n")
	}

	return nil
}

// removeChains removes the custom chain and jump rules.
func (m *Manager) removeChains() error {
	if m.config.DryRun {
		return nil
	}

	// Remove IPv4 chain
	if m.ipt4 != nil {
		if err := m.removeChain(m.ipt4); err != nil {
			return fmt.Errorf("IPv4: %w", err)
		}
	}

	// Remove IPv6 chain
	if m.ipt6 != nil {
		if err := m.removeChain(m.ipt6); err != nil {
			return fmt.Errorf("IPv6: %w", err)
		}
	}

	return nil
}

// removeChain removes the custom chain from the given iptables instance.
func (m *Manager) removeChain(ipt *iptables.IPTables) error {
	// Remove jump rules from parent chains
	for _, parentChain := range []string{"INPUT", "FORWARD", "OUTPUT"} {
		jumpRule := []string{"-j", m.chainName}

		exists, err := ipt.Exists("filter", parentChain, jumpRule...)
		if err != nil {
			continue
		}

		if exists {
			if err := ipt.Delete("filter", parentChain, jumpRule...); err != nil {
				return fmt.Errorf("failed to remove jump rule from %s: %w", parentChain, err)
			}
		}
	}

	// Delete the chain (must be empty and have no references)
	if err := ipt.DeleteChain("filter", m.chainName); err != nil {
		// Chain might not exist, just log
		if m.config.Verbose {
			fmt.Printf("[FIREWALL] Warning: failed to delete chain %s: %v\n", m.chainName, err)
		}
	}

	return nil
}
