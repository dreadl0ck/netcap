# NETCAP Rules Engine

The NETCAP Rules Engine allows you to define detection rules that automatically generate alerts when specific network patterns are observed. Rules use expr-lang expressions to match audit records and can be configured to detect various attack patterns, anomalies, and policy violations.

## Table of Contents

- [Overview](#overview)
- [Rule Configuration](#rule-configuration)
- [Writing Rules](#writing-rules)
- [Alert Structure](#alert-structure)
- [MITRE ATT&CK Integration](#mitre-attck-integration)
- [Example Rules](#example-rules)
- [Best Practices](#best-practices)

## Overview

### Features

- **Expression-based matching**: Use powerful expr-lang expressions to define detection logic
- **MITRE ATT&CK mapping**: Associate rules with MITRE ATT&CK techniques
- **Alert deduplication**: Automatic deduplication within configurable time windows
- **Rate limiting**: Prevent alert flooding with per-rule rate limits
- **Multiple severity levels**: Categorize alerts as low, medium, high, or critical
- **Flexible tagging**: Organize rules with custom tags
- **Audit record output**: Alerts are written as NETCAP audit records for analysis

### Architecture

```
┌──────────────┐
│ Audit Records│
└──────┬───────┘
       │
       ▼
┌──────────────┐
│ Rules Engine │
└──────┬───────┘
       │
       ├─► Alert (if match)
       │
       ▼
┌──────────────┐
│ Alert.ncap.gz│
└──────────────┘
```

## Rule Configuration

Rules are defined in YAML files with the following structure:

```yaml
rules:
  - name: Rule_Name
    description: Human-readable description
    type: AuditRecordType  # e.g., TCP, HTTP, DNS
    expression: expr-lang expression
    severity: low|medium|high|critical
    mitre: ["T1XXX.YYY"]  # MITRE ATT&CK IDs
    tags: ["tag1", "tag2"]
    enabled: true|false
```

### Field Reference

#### `name` (required)
Unique identifier for the rule. Used in alert generation and logging.

**Example**: `SSH_Bruteforce_Attempt`

#### `description` (required)
Human-readable explanation of what the rule detects.

**Example**: `Detect high frequency SSH connection attempts indicating possible brute force attack`

#### `type` (required)
The audit record type this rule applies to. Can be specified with or without the `NC_` prefix.

**Valid values**: `TCP`, `UDP`, `HTTP`, `DNS`, `TLS`, `IPv4`, `IPv6`, `ICMP`, etc.

**Examples**:
- `TCP` or `NC_TCP`
- `HTTP` or `NC_HTTP`

#### `expression` (required)
An expr-lang expression that evaluates to true when the rule matches. Has access to all fields of the audit record type.

**Example**: `DstPort == 22 && SYN && !ACK`

#### `severity` (required)
Alert severity level.

**Valid values**: `low`, `medium`, `high`, `critical` (case-insensitive)

#### `mitre` (optional)
Array of MITRE ATT&CK technique IDs associated with this detection.

**Format**: `["T####.###", ...]`

**Example**: `["T1110.001", "T1021.004"]`

Find technique IDs at: https://attack.mitre.org/

#### `tags` (optional)
Custom tags for organizing and categorizing rules.

**Example**: `["ssh", "bruteforce", "authentication"]`

#### `enabled` (required)
Whether the rule is active. Disabled rules are not evaluated.

**Valid values**: `true`, `false`

## Writing Rules

### Basic Rule Structure

```yaml
rules:
  - name: HTTPS_Traffic
    description: Detect HTTPS connections
    type: TCP
    expression: DstPort == 443
    severity: low
    tags: ["https", "encrypted"]
    enabled: true
```

### Using Helper Functions

Rules have access to all helper functions available in filtering:

```yaml
rules:
  - name: Private_to_Public
    description: Detect outbound traffic from private networks
    type: IPv4
    expression: IsPrivateIP(SrcIP) && IsPublicIP(DstIP)
    severity: low
    tags: ["network", "outbound"]
    enabled: true
```

### Complex Expressions

Combine multiple conditions for sophisticated detections:

```yaml
rules:
  - name: Suspicious_HTTP_Upload
    description: Detect large POST requests with suspicious user agents
    type: HTTP
    expression: |
      Method == "POST" && 
      ReqContentLength > 10000000 && 
      UserAgent in ["curl", "wget", "python"]
    severity: high
    mitre: ["T1041"]
    tags: ["exfiltration", "http"]
    enabled: true
```

### Field Access

Access nested fields using dot notation:

```yaml
rules:
  - name: DNS_Large_Query
    description: Detect DNS queries with long domain names
    type: DNS
    expression: len(Questions) > 0 && len(Questions[0].Name) > 100
    severity: medium
    mitre: ["T1071.004"]
    tags: ["dns", "tunneling"]
    enabled: true
```

## Alert Structure

When a rule matches, an alert is generated with the following information:

```go
type Alert struct {
    Timestamp      int64    // When the alert was generated
    Name           string   // Rule name
    Description    string   // Rule description
    SrcIP          string   // Source IP from matched record
    DstIP          string   // Destination IP from matched record
    SrcPort        string   // Source port from matched record
    DstPort        string   // Destination port from matched record
    MITRE          string   // MITRE ATT&CK IDs (comma-separated)
    RuleName       string   // Rule name (duplicate of Name)
    RecordType     string   // Type of audit record that matched
    Severity       string   // Alert severity level
    Tags           []string // Rule tags
    MatchedRecord  string   // JSON representation of matched record
}
```

Alerts are written to `Alert.ncap.gz` in the output directory and can be analyzed like any other audit record:

```bash
# View all alerts
net dump -read Alert.ncap.gz

# Filter critical alerts
net dump -read Alert.ncap.gz -filter "Severity == 'critical'"

# Find SSH-related alerts
net dump -read Alert.ncap.gz -filter "RuleName in ['SSH_Bruteforce_Attempt', 'SSH_Tunnel_Detection']"
```

## MITRE ATT&CK Integration

NETCAP rules can be mapped to MITRE ATT&CK tactics and techniques to provide context about detected threats.

### Common Technique Mappings

| Technique ID | Name | Use Case |
|--------------|------|----------|
| T1046 | Network Service Scanning | Port scans, service enumeration |
| T1071.001 | Web Protocols | HTTP/HTTPS C2 communication |
| T1071.004 | DNS | DNS tunneling, exfiltration |
| T1110 | Brute Force | Password guessing attacks |
| T1190 | Exploit Public-Facing Application | Web application attacks |
| T1021.004 | SSH | Remote access via SSH |
| T1041 | Exfiltration Over C2 Channel | Data exfiltration |
| T1048 | Exfiltration Over Alternative Protocol | Non-standard exfiltration methods |
| T1572 | Protocol Tunneling | Encapsulation for evasion |

### Example with MITRE Mapping

```yaml
rules:
  - name: SQL_Injection_Attempt
    description: Detect SQL injection patterns in HTTP requests
    type: HTTP
    expression: MatchesPattern(URL, "(?i)(union.*select|insert.*into|delete.*from)")
    severity: critical
    mitre: ["T1190"]  # Exploit Public-Facing Application
    tags: ["web", "sql-injection", "injection"]
    enabled: true
```

## Example Rules

### Network Reconnaissance

```yaml
rules:
  # Port Scanning
  - name: SYN_Scan
    description: Detect TCP SYN scan attempts
    type: TCP
    expression: SYN && !ACK && !RST
    severity: medium
    mitre: ["T1046"]
    tags: ["reconnaissance", "port-scan"]
    enabled: true

  # ICMP Reconnaissance
  - name: ICMP_Ping_Sweep
    description: Detect ICMP echo requests (ping sweep)
    type: ICMPv4
    expression: TypeCode == 8
    severity: low
    mitre: ["T1018"]
    tags: ["reconnaissance", "icmp"]
    enabled: true
```

### Data Exfiltration

```yaml
rules:
  # DNS Exfiltration
  - name: DNS_Tunneling
    description: Detect suspiciously large DNS queries
    type: DNS
    expression: len(Questions) > 0 && len(Questions[0].Name) > 100
    severity: high
    mitre: ["T1048.003"]
    tags: ["exfiltration", "dns", "tunneling"]
    enabled: true

  # Large Upload
  - name: Large_HTTP_Upload
    description: Detect large HTTP uploads
    type: HTTP
    expression: Method == "POST" && ReqContentLength > 50000000
    severity: high
    mitre: ["T1041"]
    tags: ["exfiltration", "http"]
    enabled: true
```

### Malware Communication

```yaml
rules:
  # IRC C2
  - name: IRC_Communication
    description: Detect IRC traffic (possible botnet C2)
    type: TCP
    expression: DstPort >= 6667 && DstPort <= 6669
    severity: high
    mitre: ["T1219"]
    tags: ["malware", "c2", "irc"]
    enabled: true

  # Suspicious Port
  - name: Backdoor_Port_31337
    description: Detect connections to common backdoor port
    type: TCP
    expression: DstPort == 31337 || SrcPort == 31337
    severity: critical
    mitre: ["T1571"]
    tags: ["malware", "backdoor"]
    enabled: true
```

### Web Attacks

```yaml
rules:
  # SQL Injection
  - name: SQL_Injection
    description: Detect SQL injection attempts
    type: HTTP
    expression: MatchesPattern(URL, "(?i)(union.*select|insert.*into)")
    severity: critical
    mitre: ["T1190"]
    tags: ["web", "sql-injection"]
    enabled: true

  # Directory Traversal
  - name: Directory_Traversal
    description: Detect path traversal attempts
    type: HTTP
    expression: MatchesPattern(URL, "\\.\\./")
    severity: high
    mitre: ["T1083"]
    tags: ["web", "path-traversal"]
    enabled: true
```

## Best Practices

### Rule Design

1. **Be Specific**: Target specific behaviors rather than broad patterns
   ```yaml
   # Good - specific
   expression: Method == "POST" && DstPort == 80 && ReqContentLength > 10000000
   
   # Bad - too broad
   expression: ReqContentLength > 0
   ```

2. **Balance False Positives**: Adjust thresholds to minimize false alerts
   ```yaml
   # May generate false positives
   expression: DstPort == 22
   
   # Better - more specific
   expression: DstPort == 22 && SYN && !ACK && IsPublicIP(SrcIP)
   ```

3. **Use Appropriate Severity**: Match severity to actual threat level
   - `low`: Informational, minor anomalies
   - `medium`: Suspicious activity, requires investigation
   - `high`: Likely malicious activity
   - `critical`: Active attacks, immediate response needed

### Rule Organization

1. **Group Related Rules**: Create separate files for different categories
   ```
   rules/
   ├── reconnaissance.yml
   ├── exfiltration.yml
   ├── malware.yml
   └── web_attacks.yml
   ```

2. **Use Descriptive Names**: Make rule purpose clear from name
   ```yaml
   # Good
   name: SSH_Bruteforce_External_Source
   
   # Bad
   name: Rule_1
   ```

3. **Add Comprehensive Tags**: Enable filtering and analysis
   ```yaml
   tags: ["protocol:ssh", "attack:bruteforce", "source:external"]
   ```

### Testing Rules

1. **Test Against Known Traffic**: Verify rules work as expected
   ```bash
   # Test rule file
   net capture -read traffic.pcap -rules test_rules.yml -out test_output
   
   # Check generated alerts
   net dump -read test_output/Alert.ncap.gz
   ```

2. **Monitor Alert Volume**: Ensure rules don't generate excessive alerts
   ```bash
   # Count alerts per rule
   net dump -read Alert.ncap.gz -csv | cut -d';' -f2 | sort | uniq -c
   ```

3. **Review False Positives**: Refine rules based on real-world results
   ```bash
   # Review specific rule alerts
   net dump -read Alert.ncap.gz -filter "RuleName == 'SSH_Bruteforce'"
   ```

### Performance Optimization

1. **Limit Regex Complexity**: Simple patterns are faster
   ```yaml
   # Fast
   expression: Method == "POST"
   
   # Slower
   expression: MatchesPattern(Method, "^(POST|PUT|DELETE)$")
   ```

2. **Order Conditions**: Place fast checks first
   ```yaml
   # Good - fast check first
   expression: DstPort == 80 && MatchesPattern(URL, "complex_regex")
   
   # Suboptimal - slow check first
   expression: MatchesPattern(URL, "complex_regex") && DstPort == 80
   ```

3. **Use Helper Functions**: Optimized native implementations
   ```yaml
   # Prefer
   expression: IsPrivateIP(SrcIP)
   
   # Over
   expression: InSubnet(SrcIP, "10.0.0.0/8") || InSubnet(SrcIP, "172.16.0.0/12")
   ```

## Troubleshooting

### Rule Not Triggering

1. **Check rule is enabled**: `enabled: true`
2. **Verify record type**: Ensure rule type matches audit records
3. **Test expression**: Use filter on dump command to test expression
4. **Check field names**: Use `-fields` flag to see available fields

### Too Many Alerts

1. **Increase specificity**: Add more conditions to reduce false positives
2. **Adjust thresholds**: Increase numeric thresholds
3. **Check deduplication**: Ensure deduplication window is appropriate

### Expression Errors

```bash
# Common errors and solutions

# Error: undefined identifier "InvalidField"
# Solution: Check available fields with -fields flag

# Error: type mismatch
# Solution: Ensure field types match comparison (string vs int)

# Error: invalid regex
# Solution: Test regex pattern separately, escape special characters
```

## Next Steps

- Review [example rules](../rules/examples/) for more patterns
- See [FILTERING.md](FILTERING.md) for expression syntax details
- Check the [expr-lang documentation](https://expr-lang.org/docs/language-definition)
- Explore MITRE ATT&CK framework at https://attack.mitre.org/

