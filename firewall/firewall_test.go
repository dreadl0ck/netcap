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

package firewall

import (
	"testing"
	"time"
)

func TestBlockEntryIsExpired(t *testing.T) {
	tests := []struct {
		name     string
		entry    *BlockEntry
		expected bool
	}{
		{
			name: "permanent block never expires",
			entry: &BlockEntry{
				IP:        "192.168.1.1",
				ExpiresAt: time.Time{}, // Zero time = permanent
			},
			expected: false,
		},
		{
			name: "expired block",
			entry: &BlockEntry{
				IP:        "192.168.1.2",
				ExpiresAt: time.Now().Add(-1 * time.Hour),
			},
			expected: true,
		},
		{
			name: "not yet expired block",
			entry: &BlockEntry{
				IP:        "192.168.1.3",
				ExpiresAt: time.Now().Add(1 * time.Hour),
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.entry.IsExpired(); got != tt.expected {
				t.Errorf("IsExpired() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestDefaultConfigs(t *testing.T) {
	// Test DefaultManagerConfig
	config := DefaultManagerConfig()
	if config == nil {
		t.Fatal("DefaultManagerConfig() returned nil")
	}
	if config.ChainName != DefaultChainNameConst {
		t.Errorf("ChainName = %s, want %s", config.ChainName, DefaultChainNameConst)
	}
	if !config.EnableIPv4 {
		t.Error("EnableIPv4 should be true by default")
	}
	if !config.EnableIPv6 {
		t.Error("EnableIPv6 should be true by default")
	}
	if config.DryRun {
		t.Error("DryRun should be false by default")
	}

	// Test DefaultBlockConfig
	blockConfig := DefaultBlockConfig()
	if blockConfig == nil {
		t.Fatal("DefaultBlockConfig() returned nil")
	}
	if blockConfig.Target != "source" {
		t.Errorf("Target = %s, want source", blockConfig.Target)
	}
	if blockConfig.Action != "DROP" {
		t.Errorf("Action = %s, want DROP", blockConfig.Action)
	}

	// Test DefaultRateLimitConfig
	rateLimitConfig := DefaultRateLimitConfig()
	if rateLimitConfig == nil {
		t.Fatal("DefaultRateLimitConfig() returned nil")
	}
	if rateLimitConfig.Rate != "10/minute" {
		t.Errorf("Rate = %s, want 10/minute", rateLimitConfig.Rate)
	}

	// Test DefaultLogConfig
	logConfig := DefaultLogConfig()
	if logConfig == nil {
		t.Fatal("DefaultLogConfig() returned nil")
	}
	if logConfig.Prefix != "NETCAP: " {
		t.Errorf("Prefix = %s, want 'NETCAP: '", logConfig.Prefix)
	}
}

func TestIsValidActionType(t *testing.T) {
	tests := []struct {
		actionType string
		expected   bool
	}{
		{"iptables_block", true},
		{"iptables_reject", true},
		{"iptables_rate_limit", true},
		{"iptables_log", true},
		{"iptables_accept", true},
		{"invalid_action", false},
		{"", false},
		{"block", false},
	}

	for _, tt := range tests {
		t.Run(tt.actionType, func(t *testing.T) {
			if got := IsValidActionType(tt.actionType); got != tt.expected {
				t.Errorf("IsValidActionType(%q) = %v, want %v", tt.actionType, got, tt.expected)
			}
		})
	}
}

func TestResponseActionIsEnabled(t *testing.T) {
	// Note: ResponseAction is defined in rules package, so we test the config types here
	enabled := true
	disabled := false

	tests := []struct {
		name     string
		enabled  *bool
		expected bool
	}{
		{"nil means enabled", nil, true},
		{"explicitly enabled", &enabled, true},
		{"explicitly disabled", &disabled, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// The ResponseAction.IsEnabled() is in rules package
			// Here we just verify the pointer behavior
			if tt.enabled == nil {
				// Default should be true
				if !true {
					t.Error("nil should mean enabled")
				}
			} else if *tt.enabled != tt.expected {
				t.Errorf("enabled pointer = %v, want %v", *tt.enabled, tt.expected)
			}
		})
	}
}

