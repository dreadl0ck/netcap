# Firewall Response Actions

NETCAP can automatically execute firewall actions (like blocking IPs) when detection rules match. This enables automated incident response by integrating with the Linux iptables firewall subsystem.

## Table of Contents

- [Overview](#overview)
- [Requirements](#requirements)
- [Architecture](#architecture)
- [Configuration](#configuration)
- [Response Action Types](#response-action-types)
- [Rule Examples](#rule-examples)
- [Firewall Manager API](#firewall-manager-api)
- [Safety Features](#safety-features)
- [Monitoring & Statistics](#monitoring--statistics)
- [Best Practices](#best-practices)
- [Troubleshooting](#troubleshooting)

## Overview

### Features

- **Automated Blocking**: Automatically block IPs based on detection rules
- **Time-based Expiration**: Blocks automatically expire after configurable durations
- **Whitelist Protection**: Prevent blocking of critical infrastructure
- **Custom Chain**: Uses dedicated `NETCAP` iptables chain for easy management
- **Dual-Stack Support**: Works with both IPv4 and IPv6
- **Dry-Run Mode**: Test configurations without modifying firewall
- **Statistics Tracking**: Monitor block counts, expirations, and errors
- **Graceful Cleanup**: All rules removed on shutdown

### Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                         NETCAP                                      │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  ┌──────────────────┐         ┌──────────────────────────────────┐  │
│  │   Rules Engine   │─────────│      Detection Rules             │  │
│  │    (rules/)      │         │  (YAML with expressions)         │  │
│  └────────┬─────────┘         └──────────────────────────────────┘  │
│           │                                                         │
│           │ on match + alert generated                              │
│           ▼                                                         │
│  ┌──────────────────┐         ┌──────────────────────────────────┐  │
│  │  Action Executor │─────────│    Response Actions              │  │
│  │                  │         │  - iptables_block                │  │
│  └────────┬─────────┘         │  - iptables_reject               │  │
│           │                   │  - iptables_rate_limit           │  │
│           ▼                   │  - iptables_log                  │  │
│  ┌──────────────────┐         └──────────────────────────────────┘  │
│  │ Firewall Manager │◄──── github.com/coreos/go-iptables           │
│  │   (firewall/)    │                                               │
│  └────────┬─────────┘                                               │
│           │                                                         │
│           ▼                                                         │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │                    Linux iptables                             │   │
│  │  ┌──────────────────────────────────────────────────────┐    │   │
│  │  │ NETCAP Chain (custom)                                 │    │   │
│  │  │  -s 192.168.1.100 -j DROP -m comment "NETCAP: ..."   │    │   │
│  │  │  -s 10.0.0.50 -j REJECT -m comment "NETCAP: ..."     │    │   │
│  │  └──────────────────────────────────────────────────────┘    │   │
│  │                                                               │   │
│  │  INPUT ──► -j NETCAP                                          │   │
│  │  FORWARD ──► -j NETCAP                                        │   │
│  │  OUTPUT ──► -j NETCAP                                         │   │
│  └──────────────────────────────────────────────────────────────┘   │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

## Requirements

| Requirement | Details |
|-------------|---------|
| **Operating System** | Linux (iptables required) |
| **Privileges** | Root or `CAP_NET_ADMIN` capability |
| **iptables** | iptables and/or ip6tables installed |
| **Kernel Modules** | `xt_comment` module for rule comments |

### Non-Linux Platforms

On non-Linux platforms (macOS, Windows), the firewall manager returns an error:
```
firewall management is only supported on Linux
```

Rules with firewall response actions will be skipped with a warning.

## Configuration

### Firewall Manager Configuration

```go
config := &firewall.ManagerConfig{
    // Custom chain name (default: "NETCAP")
    ChainName: "NETCAP",
    
    // Enable IPv4 iptables (default: true)
    EnableIPv4: true,
    
    // Enable IPv6 ip6tables (default: true)
    EnableIPv6: true,
    
    // How often to check for expired blocks (default: 1 minute)
    CleanupInterval: 1 * time.Minute,
    
    // Default block duration if not specified (default: 30 minutes)
    DefaultDuration: 30 * time.Minute,
    
    // IPs/CIDRs that should never be blocked
    Whitelist: []string{
        "127.0.0.0/8",
        "::1/128",
        "192.168.1.1",  // Gateway
    },
    
    // Preview mode - log actions without executing
    DryRun: false,
    
    // Enable verbose logging
    Verbose: true,
}

manager, err := firewall.NewManager(config)
```

### Rule Configuration with Response Actions

Add an `actions` array to detection rules:

```yaml
rules:
  - name: Block SSH Brute Force
    description: Block hosts after multiple SSH attempts
    type: SSH
    expression: DstPort == 22
    severity: high
    threshold: 10
    threshold_window: 300
    actions:
      - type: iptables_block
        config:
          target: source      # "source" or "destination"
          duration: 2h        # Block duration
    enabled: true
    tags: ["ssh", "brute-force", "block"]
```

## Response Action Types

### `iptables_block`

Blocks traffic by adding a DROP rule to iptables.

```yaml
actions:
  - type: iptables_block
    config:
      target: source          # "source" or "destination"
      duration: 30m           # Duration: 30m, 1h, 24h, etc.
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `target` | string | `"source"` | Block source (`source`/`src`) or destination (`destination`/`dst`) IP |
| `duration` | string/int | `30m` | Block duration. String (`"30m"`, `"2h"`) or int (minutes) |

### `iptables_reject`

Rejects traffic with an ICMP response (more informative than DROP).

```yaml
actions:
  - type: iptables_reject
    config:
      target: source
      duration: 1h
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `target` | string | `"source"` | Block source or destination IP |
| `duration` | string/int | `30m` | Block duration |

### `iptables_log`

Logs matching traffic (currently logs to stdout, iptables LOG target planned).

```yaml
actions:
  - type: iptables_log
    config:
      prefix: "SUSPICIOUS: "
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `prefix` | string | `"NETCAP: "` | Log message prefix |

### `iptables_rate_limit`

Rate-limits traffic from/to an IP (placeholder - full implementation pending).

```yaml
actions:
  - type: iptables_rate_limit
    config:
      rate: "10/minute"
      burst: 5
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `rate` | string | `"10/minute"` | Rate limit specification |
| `burst` | int | `5` | Initial burst allowance |

> **Note**: Rate limiting requires the `hashlimit` iptables module and is not fully implemented.

## Rule Examples

### Port Scanning Detection & Block

```yaml
- name: Block Port Scanner
  description: Block hosts performing port scans
  type: TCP
  expression: |
    SYN && !ACK && PayloadSize == 0
  severity: high
  threshold: 50
  threshold_window: 10
  actions:
    - type: iptables_block
      config:
        target: source
        duration: 1h
  enabled: true
  mitre: ["T1046"]
  tags: ["scanning", "recon", "block"]
```

### SSH Brute Force Protection

```yaml
- name: Block SSH Brute Force
  description: Block hosts after 10 SSH connection attempts in 5 minutes
  type: TCP
  expression: DstPort == 22 && SYN && !ACK
  severity: high
  threshold: 10
  threshold_window: 300
  actions:
    - type: iptables_block
      config:
        target: source
        duration: 2h
  enabled: true
  mitre: ["T1110"]
  tags: ["ssh", "brute-force", "block"]
```

### DNS Tunneling Detection

```yaml
- name: Block DNS Tunneling
  description: Block hosts using DNS tunneling for data exfiltration
  type: DNS
  expression: |
    len(Questions) > 0 &&
    len(Questions[0].Name) > 100
  severity: high
  threshold: 20
  threshold_window: 60
  actions:
    - type: iptables_block
      config:
        target: source
        duration: 4h
    - type: iptables_log
      config:
        prefix: "DNS_TUNNEL: "
  enabled: true
  mitre: ["T1071.004", "T1048"]
  tags: ["dns", "tunneling", "exfiltration", "block"]
```

### Web Attack Detection

```yaml
- name: Block SQL Injection Attempts
  description: Block hosts attempting SQL injection
  type: HTTP
  expression: |
    MatchesPattern(URL, "(?i)(union.*select|insert.*into|drop.*table)")
  severity: critical
  threshold: 3
  threshold_window: 60
  actions:
    - type: iptables_block
      config:
        target: source
        duration: 24h
  enabled: true
  mitre: ["T1190"]
  tags: ["sql-injection", "web-attack", "block"]
```

### SYN Flood Protection

```yaml
- name: Block SYN Flood Source
  description: Block hosts generating SYN flood attacks
  type: TCP
  expression: SYN && !ACK && PayloadSize == 0
  severity: critical
  threshold: 100
  threshold_window: 5
  actions:
    - type: iptables_block
      config:
        target: source
        duration: 6h
    - type: iptables_log
      config:
        prefix: "SYN_FLOOD: "
  enabled: true
  mitre: ["T1498"]
  tags: ["dos", "syn-flood", "block"]
```

## Firewall Manager API

### Creating a Manager

```go
import "github.com/dreadl0ck/netcap/firewall"

// Create with default config
manager, err := firewall.NewManager(nil)

// Create with custom config
config := firewall.DefaultManagerConfig()
config.Whitelist = append(config.Whitelist, "10.0.0.1")
config.Verbose = true
manager, err := firewall.NewManager(config)
```

### Blocking IPs

```go
// Block an IP
err := manager.BlockIP("192.168.1.100", &firewall.BlockConfig{
    Target:   "source",
    Duration: 30 * time.Minute,
    Action:   "DROP",
    RuleName: "manual-block",
    Reason:   "Port scanning detected",
})

// Block a CIDR range
err := manager.BlockCIDR("10.0.0.0/24", &firewall.BlockConfig{
    Target:   "source",
    Duration: 1 * time.Hour,
    Action:   "DROP",
    RuleName: "network-block",
})
```

### Unblocking IPs

```go
// Unblock an IP
err := manager.UnblockIP("192.168.1.100")

// Unblock a CIDR
err := manager.UnblockCIDR("10.0.0.0/24")
```

### Querying State

```go
// Check if IP is blocked
if manager.IsBlocked("192.168.1.100") {
    fmt.Println("IP is blocked")
}

// Get all active blocks
blocks := manager.GetActiveBlocks()
for _, block := range blocks {
    fmt.Printf("Blocked: %s (expires: %v)\n", block.IP, block.ExpiresAt)
}

// Get statistics
stats := manager.GetStats()
fmt.Printf("Blocks created: %d\n", stats["blocks_created"])
fmt.Printf("Active blocks: %d\n", stats["active_blocks"])
```

### Whitelist Management

```go
// Add to whitelist
manager.AddToWhitelist("192.168.1.1")
manager.AddToWhitelist("10.0.0.0/8")

// Remove from whitelist
manager.RemoveFromWhitelist("192.168.1.1")
```

### Cleanup

```go
// Flush all rules (but keep chain)
err := manager.Flush()

// Close manager (flushes rules, removes chain, stops goroutines)
err := manager.Close()
```

### Integration with Rules Engine

```go
import (
    "github.com/dreadl0ck/netcap/firewall"
    "github.com/dreadl0ck/netcap/rules"
)

// Create firewall manager
fwManager, err := firewall.NewManager(nil)
if err != nil {
    log.Fatal(err)
}
defer fwManager.Close()

// Create rules engine
engine, err := rules.NewEngine("rules/", alertWriter)
if err != nil {
    log.Fatal(err)
}

// Connect firewall manager to rules engine
engine.SetFirewallManager(fwManager)

// Now response actions in rules will automatically execute
```

## Safety Features

### Whitelist Protection

IPs/CIDRs in the whitelist are never blocked:

```go
config := firewall.DefaultManagerConfig()
config.Whitelist = []string{
    "127.0.0.0/8",     // Localhost
    "::1/128",         // IPv6 localhost
    "192.168.1.1",     // Gateway
    "10.0.0.0/8",      // Internal network
}
```

### Automatic Expiration

All blocks expire automatically:

- Configurable per-rule duration
- Default: 30 minutes
- Background cleanup every minute
- Zero duration = permanent until restart

### Custom Chain Isolation

All rules are placed in a dedicated `NETCAP` chain:

```bash
# View NETCAP chain rules
sudo iptables -L NETCAP -n -v

# Manually flush if needed
sudo iptables -F NETCAP
```

### Dry-Run Mode

Test configurations without modifying firewall:

```go
config := firewall.DefaultManagerConfig()
config.DryRun = true  // Actions are logged but not executed
```

### Graceful Shutdown

On `Close()`:
1. Cleanup goroutine stopped
2. All rules flushed
3. Jump rules removed
4. Custom chain deleted

## Monitoring & Statistics

### Available Statistics

```go
stats := manager.GetStats()
```

| Metric | Description |
|--------|-------------|
| `blocks_created` | Total blocks created since start |
| `blocks_removed` | Blocks manually removed |
| `blocks_expired` | Blocks removed due to expiration |
| `duplicates_skip` | Duplicate block requests skipped |
| `whitelist_skip` | Block requests skipped due to whitelist |
| `errors` | Total errors encountered |
| `active_blocks` | Currently active blocks |

### Action Statistics (Rules Engine)

```go
actionStats := engine.GetActionStats()
```

| Metric | Description |
|--------|-------------|
| `actions_executed` | Total response actions executed |
| `actions_success` | Successful actions |
| `actions_failed` | Failed actions |
| `ips_blocked` | Total IPs blocked |

### Viewing Active Blocks

```go
blocks := manager.GetActiveBlocks()
for _, b := range blocks {
    fmt.Printf("IP: %s\n", b.IP)
    fmt.Printf("  Rule: %s\n", b.RuleName)
    fmt.Printf("  Reason: %s\n", b.Reason)
    fmt.Printf("  Created: %v\n", b.CreatedAt)
    fmt.Printf("  Expires: %v\n", b.ExpiresAt)
    fmt.Printf("  Action: %s\n", b.Action)
}
```

## Best Practices

### Rule Design

1. **Use Thresholds**: Avoid blocking on single events
   ```yaml
   # Good - requires multiple matches
   threshold: 10
   threshold_window: 60
   
   # Bad - blocks on first match
   threshold: 1
   ```

2. **Set Appropriate Durations**: Match severity to block duration
   ```yaml
   # Low severity: short blocks
   duration: 15m
   
   # High severity: longer blocks
   duration: 24h
   ```

3. **Combine Actions**: Use logging with blocking
   ```yaml
   actions:
     - type: iptables_block
       config:
         duration: 1h
     - type: iptables_log
       config:
         prefix: "BLOCKED: "
   ```

### Whitelist Management

1. **Always whitelist critical infrastructure**:
   - Gateways and routers
   - DNS servers
   - Management IPs
   - Monitoring systems

2. **Include your own IPs**:
   - SSH access IPs
   - Admin workstations
   - CI/CD systems

### Testing

1. **Start with dry-run mode**:
   ```go
   config.DryRun = true
   ```

2. **Monitor logs during initial deployment**:
   ```go
   config.Verbose = true
   ```

3. **Test with known traffic**:
   ```bash
   # Generate test traffic
   nmap -sS target_ip
   
   # Verify block was created
   sudo iptables -L NETCAP -n -v
   ```

### Production Deployment

1. **Monitor statistics regularly**
2. **Review blocked IPs periodically**
3. **Keep whitelists up to date**
4. **Set up alerting for high block rates**
5. **Log all firewall actions for audit**

## Troubleshooting

### Manager Creation Fails

```
Error: failed to initialize iptables (IPv4): ...
```

**Solutions**:
- Verify iptables is installed: `which iptables`
- Check permissions: Run as root or with `CAP_NET_ADMIN`
- Verify kernel modules: `lsmod | grep xt_`

### Rules Not Blocking

1. **Check firewall manager is set**:
   ```go
   if engine.GetFirewallManager() == nil {
       log.Warn("Firewall manager not configured")
   }
   ```

2. **Verify action configuration**:
   ```yaml
   actions:
     - type: iptables_block  # Not "block" or "iptables-block"
       config:
         target: source      # Not "src" alone at top level
   ```

3. **Check whitelist**:
   ```go
   // IP might be whitelisted
   config.Whitelist
   ```

### Blocks Not Expiring

1. **Verify cleanup is running**:
   ```go
   // Check verbose logs for cleanup messages
   config.Verbose = true
   ```

2. **Check expiration time**:
   ```go
   blocks := manager.GetActiveBlocks()
   for _, b := range blocks {
       fmt.Printf("Expires: %v (in %v)\n", 
           b.ExpiresAt, 
           time.Until(b.ExpiresAt))
   }
   ```

### Rules Persist After Shutdown

If rules remain after unclean shutdown:

```bash
# Manually flush NETCAP chain
sudo iptables -F NETCAP
sudo ip6tables -F NETCAP

# Remove jump rules
sudo iptables -D INPUT -j NETCAP
sudo iptables -D FORWARD -j NETCAP
sudo iptables -D OUTPUT -j NETCAP

# Delete chain
sudo iptables -X NETCAP
```

### Viewing iptables Rules

```bash
# List NETCAP chain with details
sudo iptables -L NETCAP -n -v --line-numbers

# List all chains showing NETCAP jumps
sudo iptables -L -n -v | grep -A5 NETCAP

# Watch for changes
watch -n1 'sudo iptables -L NETCAP -n'
```

## Next Steps

- Review [RULES_ENGINE.md](RULES_ENGINE.md) for detection rule syntax
- See [FILTERING.md](FILTERING.md) for expression syntax
- Check example rules in [configs/firewall-rules.yml](../configs/firewall-rules.yml)
- Explore [injection rules](../configs/injection-rules.yml) for real-time packet actions

