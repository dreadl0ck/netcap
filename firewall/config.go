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
	"time"
)

const (
	// DefaultBlockDurationConfig is the default duration for blocks if not specified.
	DefaultBlockDurationConfig = 30 * time.Minute

	// DefaultChainName is the custom chain name for netcap-managed rules.
	DefaultChainNameConst = "NETCAP"

	// DefaultCleanupIntervalConst is how often expired blocks are cleaned up.
	DefaultCleanupIntervalConst = 1 * time.Minute
)

// Protocol represents the IP protocol version.
type Protocol int

const (
	// ProtocolIPv4 represents IPv4.
	ProtocolIPv4 Protocol = iota
	// ProtocolIPv6 represents IPv6.
	ProtocolIPv6
)

// BlockEntry represents an active firewall block.
type BlockEntry struct {
	// IP is the blocked IP address.
	IP string

	// CIDR is the blocked CIDR range (if blocking a range).
	CIDR string

	// CreatedAt is when the block was created.
	CreatedAt time.Time

	// ExpiresAt is when the block will automatically be removed (zero means permanent).
	ExpiresAt time.Time

	// RuleName is the netcap rule that triggered this block.
	RuleName string

	// Reason is a human-readable reason for the block.
	Reason string

	// Chain is the iptables chain where the rule was added.
	Chain string

	// Target is whether this blocks source or destination.
	Target string

	// Action is DROP or REJECT.
	Action string
}

// IsExpired returns true if the block has expired.
func (b *BlockEntry) IsExpired() bool {
	if b.ExpiresAt.IsZero() {
		return false // Permanent block
	}
	return time.Now().After(b.ExpiresAt)
}

// ManagerConfig holds configuration for the firewall manager.
type ManagerConfig struct {
	// ChainName is the custom chain name (default: NETCAP).
	ChainName string

	// EnableIPv4 enables IPv4 iptables (default: true).
	EnableIPv4 bool

	// EnableIPv6 enables IPv6 ip6tables (default: true).
	EnableIPv6 bool

	// CleanupInterval is how often to check for expired blocks.
	CleanupInterval time.Duration

	// DefaultDuration is the default block duration if not specified.
	DefaultDuration time.Duration

	// Whitelist is a list of IPs/CIDRs that should never be blocked.
	Whitelist []string

	// DryRun if true, logs actions but doesn't execute them.
	DryRun bool

	// Verbose enables verbose logging.
	Verbose bool
}

// DefaultManagerConfig returns a sane default configuration.
func DefaultManagerConfig() *ManagerConfig {
	return &ManagerConfig{
		ChainName:       DefaultChainNameConst,
		EnableIPv4:      true,
		EnableIPv6:      true,
		CleanupInterval: DefaultCleanupIntervalConst,
		DefaultDuration: DefaultBlockDurationConfig,
		Whitelist:       []string{"127.0.0.0/8", "::1/128"},
		DryRun:          false,
		Verbose:         false,
	}
}

// Stats tracks firewall manager statistics.
type Stats struct {
	BlocksCreated  uint64
	BlocksRemoved  uint64
	BlocksExpired  uint64
	DuplicatesSkip uint64
	WhitelistSkip  uint64
	Errors         uint64
}

// BlockConfig configures a block action.
type BlockConfig struct {
	// Target specifies what to block: "source" or "destination"
	Target string

	// Duration is how long the block should last (0 = permanent until cleanup)
	Duration time.Duration

	// Chain is the iptables chain to use (INPUT, FORWARD, OUTPUT)
	// This is informational as we use a custom chain
	Chain string

	// Action is DROP or REJECT
	Action string

	// RuleName is the name of the rule that triggered this block
	RuleName string

	// Reason is a human-readable reason for the block
	Reason string
}

// DefaultBlockConfig returns a default block configuration.
func DefaultBlockConfig() *BlockConfig {
	return &BlockConfig{
		Target:   "source",
		Duration: DefaultBlockDurationConfig,
		Chain:    "INPUT",
		Action:   "DROP",
		RuleName: "manual",
		Reason:   "",
	}
}

// RateLimitConfig configures rate limiting.
type RateLimitConfig struct {
	// Target specifies what to rate limit: "source" or "destination"
	Target string

	// Rate is the rate limit (e.g., "10/minute", "100/second")
	Rate string

	// Burst is the initial burst allowance
	Burst int

	// Duration is how long the rate limit should last
	Duration time.Duration

	// Chain is the iptables chain to use
	Chain string

	// RuleName is the name of the rule that triggered this rate limit
	RuleName string
}

// DefaultRateLimitConfig returns a default rate limit configuration.
func DefaultRateLimitConfig() *RateLimitConfig {
	return &RateLimitConfig{
		Target:   "source",
		Rate:     "10/minute",
		Burst:    5,
		Duration: 30 * time.Minute,
		Chain:    "INPUT",
		RuleName: "manual",
	}
}

// LogConfig configures logging actions.
type LogConfig struct {
	// Target specifies what to log: "source" or "destination"
	Target string

	// Prefix is the log prefix for identifying netcap logs
	Prefix string

	// Level is the log level (0-7)
	Level int

	// RuleName is the name of the rule that triggered this log
	RuleName string
}

// DefaultLogConfig returns a default log configuration.
func DefaultLogConfig() *LogConfig {
	return &LogConfig{
		Target:   "source",
		Prefix:   "NETCAP: ",
		Level:    4, // Warning
		RuleName: "manual",
	}
}

// ActionType represents the type of firewall action.
type ActionType string

const (
	// ActionTypeBlock blocks traffic (DROP).
	ActionTypeBlock ActionType = "iptables_block"

	// ActionTypeReject rejects traffic with ICMP response.
	ActionTypeReject ActionType = "iptables_reject"

	// ActionTypeRateLimit rate-limits traffic.
	ActionTypeRateLimit ActionType = "iptables_rate_limit"

	// ActionTypeLog logs matching traffic.
	ActionTypeLog ActionType = "iptables_log"

	// ActionTypeAccept explicitly accepts traffic.
	ActionTypeAccept ActionType = "iptables_accept"
)

// IsValidActionType checks if an action type is valid.
func IsValidActionType(actionType string) bool {
	switch ActionType(actionType) {
	case ActionTypeBlock, ActionTypeReject, ActionTypeRateLimit, ActionTypeLog, ActionTypeAccept:
		return true
	default:
		return false
	}
}

