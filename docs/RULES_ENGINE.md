# Rules, correlation and alert delivery

Rules are YAML files with expr-lang expressions that match audit records. When a record matches, netcap writes an alert to `Alert.ncap.gz`.

## First rule

This rule flags HTTP requests from command-line clients such as curl, wget and Python scripts. On a capture from an office LAN, those are usually updaters, scripts or a download from a malware sample. Save it as `scripted-http.yml`:

```yaml
rules:
  - name: Scripted HTTP Client
    description: HTTP request from curl, wget or a Python HTTP library
    type: HTTP
    expression: MatchesPattern(UserAgent, "(?i)^(curl/|wget/|python[-/])")
    severity: low
    tags: [scripting, http]
    enabled: true
```

Run it on a capture and read the alerts:

```sh
net capture -read office-lan.pcap -out rule-audit -rules scripted-http.yml \
  -dpi=false -geoDB=false
net dump -read rule-audit/Alert.ncap.gz -json
```

Check `RuleName`, the matched-record evidence and the record-time timestamps. Deduplication can reduce the number of alerts, so alert rows don't map one-to-one to matched packets.

Run a new rule on a capture of normal traffic first to see how often it fires.

## Overview

* **Expression-based matching**: expr-lang expressions define the detection logic.
* **Ordered correlation**: require an earlier related record before a rule alerts.
* **MITRE ATT\&CK mapping**: attach ATT\&CK technique IDs to rules.
* **Deduplication**: repeated alerts are merged within a configurable time window.
* **Rate limiting**: a per-rule limit prevents alert floods.
* **Severity levels**: low, medium, high or critical.
* **Tags**: organize rules with your own tags.
* **Audit record output**: alerts are written as NETCAP audit records.

Audit records go into the rules engine, and matches are written to `Alert.ncap.gz`.

## Scoped capture-time rules

Capture-time evaluation adds ordered, windowed counting to `capture -rules FILE`. It handles one capture and source scope. Use a separate engine for each interface, VLAN or capture. The CLI rejects multiple input files in this mode. The scope is a label you set and netcap does not verify it. For mixed interface or VLAN input, the collector must route records to the right engine by observed scope.

```yaml
capture_time:
  scope: capture-001/sensor-01/interface-0/vlan-20
  lateness_seconds: 600
rules:
  - name: Scoped SYN observations
    type: TCP
    expression: SYN
    enabled: true
    threshold: 50
    threshold_window: 600
    group_by: [SrcIP, DstIP, DstPort]
```

| Topic         | Behavior                                                                                                                                                                                                                                                                                                                                                             |
| ------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Group/window  | `group_by` keys are string or integer fields. Counters are kept per scope and rule name. Windows are inclusive and reset each time they are crossed. Pick fields that identify the service or account. Records with a missing string key don't join.                                                                                                                 |
| Reordering    | `lateness_seconds` holds records with equal times together and sorts them by timestamp, type and protobuf bytes. A record older than the watermark fails with an error. Replays within the allowance give the same crossings. Lateness beyond it is unsupported.                                                                                                     |
| Limits        | 4,096 queued records, 1 MiB protobuf frame, 32 MiB reorder storage, 10,000 scoped groups and 100,000 pending count timestamps. Beyond these, `ErrStateCapacity` is returned. These limit rule state, not total process memory.                                                                                                                                       |
| Reload        | If the new rules fail to compile, pending state is kept. After a successful reload, admitted records drain under the old rules, then correlation, dedup and rate state reset. A change of scope or lateness needs a new engine.                                                                                                                                      |
| Finalization  | `Engine.Finalize()` drains pending records before readiness. `Close()` also drains and reports errors. The capture CLI returns finalization errors. Code that embeds the engine must call `Finalize()` before it writes `audit-output-ready.json`.                                                                                                                   |
| API           | `NewOrderedStream` gives you `Advance(watermark)` and `Finish()`. `Reload` on an explicit stream refuses pending records. `EvaluateScoped` needs records that are already ordered.                                                                                                                                                                                   |
| Compatibility | Without `capture_time`, the default rule semantics apply. Capture-time mode needs typed `after_type` sequences and rejects distinct-cardinality rules. Wall-clock dedup and rate limiting are off in scoped evaluation. Scoped count and join rules loaded by `NewEngine` need `capture_time`. Offline rule packs (`netcap-offline-rules/v1`) keep their own format. |

`sequence.after_type` and `sequence.after_group_by` add exact joins across record types. The mapped scalar types must agree, and `sequence.group_by` names the fields of the triggering record. For example, to alert on a rejected login: `after_type: Secret`, `after: AuthSuccessSet && !AuthSuccess`, `after_group_by: [CommunityID]`, `group_by: [CommunityID]`, `within: 60`.

`CommunityID` identifies a tuple only. If tuples can be reused, join on a session or transaction key. The alert's `Notes.netcapJoin` keeps two hash-only contributors, and the scope separates unrelated captures. Scoped matched-record projections keep only time, type, endpoints, CommunityID and the hash of the full record, so application headers, bodies and credentials don't end up in these alerts.

`Secret` records keep every occurrence. See [credential observations](credential-analysis.md). Secret alert projections and Prometheus labels exclude credential material.

## Durable webhook delivery

`net investigate deliver-alerts` sends redacted notices from saved alert output to a webhook:

```sh
net investigate deliver-alerts -read ./audit -outbox ./private-alert-outbox \
  -scope capture-001/sensor-01 -endpoint https://receiver.example/alerts \
  -limit 1000 -timeout 1m
```

| Topic           | Behavior                                                                                                                                                                                                                                                                                                                                  |
| --------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Opt-in          | Notices are queued only by this command. Delivery is serial POST attempts with bounded retries. No background worker runs and no destination is preconfigured.                                                                                                                                                                            |
| Durable retries | A private SQLite database (`synchronous(FULL)`) keeps pending attempts, due times and delivered or rejected receipts across restarts. Run the same command again to retry. 408, 425, 429, 5xx and transport failures retry with exponential backoff from 1 s up to 1 h. Other non-2xx responses are rejected. Redirects are not followed. |
| Idempotency     | `Idempotency-Key` is a stable SHA-256 of the notice. Identical notices share one receipt. Delivery is at least once: if the receiver accepts a POST and the sender crashes before it saves the receipt, the POST repeats. Receivers must deduplicate on that key.                                                                         |
| Limits          | 10,000 entries including receipts, 4 KiB per notice, a 64 MiB SQLite database, a 5 s request timeout and 4 KiB of response drained. When the outbox is full, new notices are refused and receipts are never evicted. Source scanning is limited by `-limit` (maximum 10,000).                                                             |
| Credentials     | `NETCAP_ALERT_WEBHOOK_TOKEN` supplies an optional bearer token at runtime. URLs can't contain userinfo, a query or a fragment. Each outbox is pinned to the digest of its destination. Notices leave out raw records, descriptions, expressions, tags, notes and credential fields. Transport errors don't echo URLs, tokens or bodies.   |
| Outcome         | The JSON report shows pending, delivered and rejected counts. Pending or rejected notices give a nonzero exit code. Rejected receipts need an operator to inspect them and are not retried. `iptables_rate_limit` and `iptables_log` return `ErrUnsupportedResponseAction`.                                                               |

## Offline grouped thresholds

`net investigate rules` evaluates `netcap-offline-rules/v1` packs against a completed capture. The format differs from the capture-time YAML above. It rejects actions, sequences and distinct gates, and the capture engine rejects offline packs.

This example counts SYN packets per source, destination and port in a capture from your network:

```sh
net capture -read office-lan.pcap -out ./audit -include TCP -context=true \
  -capture-evidence=true -dpi=false -geoDB=false -http ""
net investigate rules -read ./audit -rules grouped.yaml
```

Save this pack as `grouped.yaml`:

```yaml
format: netcap-offline-rules/v1
rules:
  - id: tcp-syn-volume
    name: Retained TCP SYN volume
    type: TCP
    expression: SYN && !ACK
    severity: medium
    enabled: true
    threshold:
      count: 50
      window: 600s
      group_by: [SrcIP, DstIP, DstPort]
```

It counts stored SYN packets, retransmissions included.

| Topic         | Behavior                                                                                                                                                                                                                                                                |
| ------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Admission     | Needs a matching finalized `capture-manifest.json` and `audit-output-ready.json`, one completed scope, no scope overflow and no offline BPF. Captures without the readiness marker must be captured again. Don't create a marker by hand.                               |
| Types         | TCP, UDP, DNS and HTTP. Missing required files give partial coverage. Corrupt input fails before anything is published.                                                                                                                                                 |
| Grouping      | 1 to 8 unique Go scalar field names, strings and integers only. An empty string withholds the observation and marks coverage partial. Numeric zero is valid. Aliases and nested fields are rejected.                                                                    |
| Expressions   | Scalar comparisons, boolean operators, `contains`, `startsWith`, `endsWith` and `in` with a literal array. Calls, methods, maps, iteration, arithmetic and regex are rejected, even in disabled rules.                                                                  |
| Windows       | Positive capture timestamps. Observations are sorted by time and canonical content. The window is inclusive, `[t-window,t]`. The Nth match alerts and resets only that group. There is no wall-clock rate limiting or deduplication.                                    |
| Configuration | One strict YAML document. Stable unique IDs, count 2 to 65,536, positive duration up to 720h (default 60s). At least one rule must be enabled.                                                                                                                          |
| Identity      | Event IDs bind the canonical retained input, the observation policy, the normalized pack, the group and the crossing. Workers, source paths and run IDs are provenance only and don't change an event's identity.                                                       |
| Output        | `Alert.ncap.gz` in the output root plus `rule-evaluations/<id>.json`. The CLI prints a JSON report. Failures and partial coverage give a nonzero exit code.                                                                                                             |
| Evidence      | The trigger JSON and digest are unchanged. `Notes.netcapOffline` holds the grouping, time bounds and up to 16 contributor references, and says when it was truncated. Nanoseconds, ordinals and counters are decimal strings. Integer groups hold typed decimal values. |
| Concurrency   | Evaluation, alert clearing and reanalysis share an output lease. Inspect a stale `.offline-rule-evaluation.lock` by hand. It is not removed automatically.                                                                                                              |

| Default refusal limit         | Value                             |
| ----------------------------- | --------------------------------- |
| Rules / records               | 64 / 100,000 per execution        |
| Frame / decoded bytes         | 4 MiB / 256 MiB                   |
| Sort data / state             | 128 MiB per type / 64 MiB         |
| Groups                        | 4,096 per rule / 16,384 per job   |
| Pending matches               | 65,536 per rule / 262,144 per job |
| Alerts / time                 | 10,000 or 32 MiB / 2 minutes      |
| Group key / execution history | 1,024 bytes / 100 reports         |

These limit accounted storage, not process memory. A job over a limit is refused and does not spill to disk. Evaluation covers the retained audit records, so records that were filtered out or discarded during capture can't be recovered.

Publication is durable for each alert, not transactional across the job. A `publish-failed` report records the prefix that was committed. A `committing` state after an interruption means the progress is unknown. Inspect the report and the alert history before you retry. Each explicit rerun appends another evaluation.

The WebUI Rules page accepts a YAML upload, validates a read-only preview and runs it against the selected completed capture. Alerts show their grouped evidence and warn about incomplete history. The routes are `GET /api/rules/offline/packs`, `POST /api/rules/offline/validate`, `POST /api/rules/offline/execute` and `GET /api/rules/offline/evaluations`. POST bodies hold `yaml` and an optional local `inputFile` or service `sessionId`. An unknown selector never falls back to a different capture. If the backend does not support offline rules, the panel is disabled.

## Rule Configuration

Rules are defined in YAML:

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

Unique name of the rule. Used in alerts and logging.

**Example**: `SSH_Bruteforce_Attempt`

#### `description` (required)

What the rule detects.

**Example**: `Detect high frequency SSH connection attempts indicating possible brute force attack`

#### `type` (required)

The audit record type the rule applies to, with or without the `NC_` prefix. Use real record names such as `TCP`, `UDP`, `HTTP`, `DNS`, `TLSClientHello`, `IPv4`, `IPv6` or `ICMPv4`. Generic names such as `TLS` and `ICMP` don't work. List the fields of a record type with `dump -fields`, and find their types in `types/netcap.proto`.

**Examples**: `TCP` or `NC_TCP`, `HTTP` or `NC_HTTP`

#### `expression` (required)

An expr-lang expression that is true when the rule matches. It can use all fields of the record type.

**Example**: `DstPort == 22 && SYN && !ACK`

#### `severity` (required)

Alert severity: `low`, `medium`, `high` or `critical` (case-insensitive).

#### `mitre` (optional)

A list of MITRE ATT\&CK technique IDs, for example `["T1110.001", "T1021.004"]`. Look up IDs at https://attack.mitre.org/.

#### `tags` (optional)

Tags for organizing rules, for example `["ssh", "bruteforce", "authentication"]`.

#### `enabled` (required)

`true` or `false`. Disabled rules are not evaluated.

#### `threshold` / `threshold_window` (optional)

Alert only after `threshold` matches within `threshold_window` seconds (default 60). These counters are shared per rule name and are not grouped by host. They use record timestamps when available, but arrival order and wall-clock suppression still apply. For deterministic counting per entity on finalized records, use [offline grouped thresholds](RULES_ENGINE.md#offline-grouped-thresholds).

#### `distinct_field` / `distinct_threshold` (optional)

Fan-out detection. The engine counts the **distinct values** of `distinct_field` seen **per source IP** within `threshold_window`, and alerts when the count reaches `distinct_threshold` (default 2). This finds one source touching many destinations, for example an internal host sweeping many controllers:

```yaml
- name: S7comm Horizontal Enumeration
  type: Connection
  expression: DstPort == "102" && !IsApprovedWorkstation(SrcIP)
  distinct_field: DstIP
  distinct_threshold: 5
  threshold_window: 300
  severity: high
  enabled: true
```

#### `sequence` (optional)

Require an earlier **related** record before the rule can alert: "B after A within a window, for the same group". For example, a write to a register that the same source read minutes earlier.

```yaml
sequence:
  after: <expression identifying the earlier record>
  group_by: [SrcIP, DstIP, UnitID, Bank, Address]
  within: 900   # seconds, default 60
```

* `after` (required): expression for the **earlier** record. It is compiled against the rule's record type, so both expressions see the same fields. The rule's own `expression` is the **trigger**.
* `group_by` (required, at least one field): top-level record fields that must be equal on the earlier and the triggering record.
* `within` (optional): how many seconds the earlier record stays eligible. Default 60. A negative value is rejected when the rules load.

How it behaves:

* The sequence check runs before `threshold` and `distinct_field` counting, so those only see completed sequences. Rules without a `sequence` block are unaffected.
* `after` is evaluated on every record of the rule's type, not only on records that match the trigger. The earlier record usually does not match the rule's own `expression`.
* `group_by` compares values for equality (string and integer fields). It can't express range overlap. Grouping on a start address pairs a write with an earlier read of the same start address, never with a read whose span merely overlaps it.
* A record that matches both `expression` and `after` can't satisfy its own precondition. It can only gate later records.
* If any `group_by` field is empty or is neither a string nor an integer, the record is not correlated, neither as trigger nor as precondition.
* Windows use the record's own timestamp, and the wall clock only for records without one, so offline replay behaves like live capture. A trigger timestamped before its precondition does not match. A gap of exactly `within` matches, and one second more does not.
* The engine must have seen the precondition before the trigger. Record types written when a stream completes or flushes can reach the engine out of timestamp order, and such pairs don't match.
* Earlier records are not consumed. One earlier record can gate every trigger in its group until the window expires, and a newer `after` match refreshes the group's timestamp.
* Tracking is per rule and per group. Aged-out groups are cleaned up periodically and the number of groups is capped. Hitting the cap means missed correlations, not unbounded memory.
* The alert describes only the triggering record. Look up the earlier record in the audit records using the group fields and the window.

The web UI can't author sequences yet, but it keeps them when you save rules or toggle rule sets.

**Worked example**, shipped disabled as [`modbus_hunt.yml`](https://github.com/dreadl0ck/netcap/blob/v0.15.2/internal/rules/examples/modbus_hunt.yml):

```yaml
- name: Modbus Write After Read Same Register
  description: A source wrote a holding register it read within the last 15 minutes, on the same destination and unit.
  type: Modbus
  expression: >-
    MessageRole == "request" && ParseStatus == "valid" && !Exception &&
    FunctionCode in [6, 16, 22] && Bank == "holding_registers" && HasAddress
  sequence:
    after: >-
      MessageRole == "request" && ParseStatus == "valid" && !Exception &&
      FunctionCode == 3 && Bank == "holding_registers" && HasAddress
    group_by: [SrcIP, DstIP, UnitID, Bank, Address]
    within: 900
  severity: medium
  tags: [modbus, write, sequence]
  enabled: false
```

Take an engineering workstation at `10.0.0.10` reading and writing registers on a PLC at `10.0.0.20`, unit 1, bank `holding_registers`:

| Earlier record                | Trigger                                   | Alert?                                                    |
| ----------------------------- | ----------------------------------------- | --------------------------------------------------------- |
| FC3 read of address 40 at `t` | FC6 write of address 40 at `t+600`        | yes                                                       |
| FC3 read of address 40 at `t` | FC6 write of address 40 at `t+901`        | no: outside `within`                                      |
| FC3 read of address 40 at `t` | FC6 write of address 41 at `t+600`        | no: grouping is equality, even if the read covered 40..45 |
| FC3 read of address 40 at `t` | FC6 write of address 40 by another source | no: `SrcIP` is in `group_by`                              |
| none                          | FC6 write of address 40                   | no                                                        |

### Additional helper functions

Besides the network, string and time helpers, expressions can use:

* `IsApprovedWorkstation(ip)` / `InAllowlist(ip)`: true if `ip` is in the approved-workstation allowlist loaded with `-approved-workstations` (`net capture`). Negate it (`!IsApprovedWorkstation(SrcIP)`) to escalate activity from unauthorized sources. See [S7 Threat Hunt](s7-threat-hunt-AA26-231A.md).
* `HourOfDay(ts)`: local hour 0 to 23 of a nanosecond timestamp.
* `Weekday(ts)`: local weekday, 0 (Sunday) to 6 (Saturday).
* `IsBusinessHours(ts, startHour, endHour)`: true within `[startHour, endHour)` on Monday to Friday. Use `!IsBusinessHours(Timestamp, 8, 18)` to find off-hours activity.

## Writing Rules

### Basic Rule Structure

```yaml
rules:
  - name: TCP_443_Observation
    description: TCP traffic to port 443
    type: TCP
    expression: DstPort == 443
    severity: low
    tags: ["https", "encrypted"]
    enabled: true
```

### Using Helper Functions

Rules can use all the helper functions available in filtering:

```yaml
rules:
  - name: Private_to_Public
    description: Outbound traffic from private networks
    type: IPv4
    expression: IsPrivateIP(SrcIP) && IsPublicIP(DstIP)
    severity: low
    tags: ["network", "outbound"]
    enabled: true
```

### Complex Expressions

Combine conditions to narrow a rule:

```yaml
rules:
  - name: Suspicious_HTTP_Upload
    description: Large POST requests from command-line user agents
    type: HTTP
    expression: |
      Method == "POST" && 
      ReqContentLength > 10000000 && 
      MatchesPattern(UserAgent, "(?i)^(curl/|wget/|python[-/])")
    severity: high
    mitre: ["T1041"]
    tags: ["exfiltration", "http"]
    enabled: true
```

### Field Access

Access nested fields with dot notation:

```yaml
rules:
  - name: DNS_Large_Query
    description: DNS queries with long domain names
    type: DNS
    expression: len(Questions) > 0 && len(Questions[0].Name) > 100
    severity: medium
    mitre: ["T1071.004"]
    tags: ["dns", "tunneling"]
    enabled: true
```

## Alert Structure

When a rule matches, netcap writes an alert with these fields:

```go
type Alert struct {
    Timestamp      int64    // Matched record time, Unix nanoseconds
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

This is an excerpt. Alerts also carry `DetectedAt` (processing time), `TimestampBasis`, `RuleDigest`, `RuleExpression`, the threshold configuration and evidence references. Read the emitted fields before you join alerts across captures.

Alerts go to `Alert.ncap.gz` in the output directory and can be analyzed like any other audit record:

```bash
# View all alerts
net dump -read Alert.ncap.gz

# Filter critical alerts
net dump -read Alert.ncap.gz -filter "Severity == 'critical'"

# Find SSH-related alerts
net dump -read Alert.ncap.gz -filter "RuleName in ['SSH_Bruteforce_Attempt', 'SSH_Tunnel_Detection']"
```

## MITRE ATT\&CK Integration

Map rules to MITRE ATT\&CK techniques to give alerts context.

### Common Technique Mappings

| Technique ID | Name                                   | Use Case                          |
| ------------ | -------------------------------------- | --------------------------------- |
| T1046        | Network Service Scanning               | Port scans, service enumeration   |
| T1071.001    | Web Protocols                          | HTTP/HTTPS C2 communication       |
| T1071.004    | DNS                                    | DNS tunneling, exfiltration       |
| T1110        | Brute Force                            | Password guessing attacks         |
| T1190        | Exploit Public-Facing Application      | Web application attacks           |
| T1021.004    | SSH                                    | Remote access via SSH             |
| T1041        | Exfiltration Over C2 Channel           | Data exfiltration                 |
| T1048        | Exfiltration Over Alternative Protocol | Non-standard exfiltration methods |
| T1572        | Protocol Tunneling                     | Encapsulation for evasion         |

### Example with MITRE Mapping

```yaml
rules:
  - name: SQL_Injection_Attempt
    description: SQL injection patterns in HTTP requests
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
  - name: TCP_SYN_Observation
    description: Initiating SYN packets. Add a threshold to detect scans
    type: TCP
    expression: SYN && !ACK && !RST
    severity: medium
    mitre: ["T1046"]
    tags: ["reconnaissance", "port-scan"]
    enabled: true

  # ICMP Reconnaissance
  - name: ICMP_Echo_Request
    description: ICMP echo requests. Count distinct destinations to find a sweep
    type: ICMPv4
    expression: Type == 8
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
    description: Very long DNS query names
    type: DNS
    expression: len(Questions) > 0 && len(Questions[0].Name) > 100
    severity: high
    mitre: ["T1048.003"]
    tags: ["exfiltration", "dns", "tunneling"]
    enabled: true

  # Large Upload
  - name: Large_HTTP_Upload
    description: Large HTTP uploads
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
  - name: TCP_IRC_Port_Observation
    description: TCP traffic to the common IRC ports 6667 to 6669
    type: TCP
    expression: DstPort >= 6667 && DstPort <= 6669
    severity: low
    tags: ["port-observation", "irc-candidate"]
    enabled: true

  # Suspicious Port
  - name: TCP_31337_Observation
    description: TCP traffic on port 31337, used by some older tools
    type: TCP
    expression: DstPort == 31337 || SrcPort == 31337
    severity: low
    tags: ["port-observation"]
    enabled: true
```

### Web Attacks

```yaml
rules:
  # SQL Injection
  - name: SQL_Injection
    description: SQL injection attempts
    type: HTTP
    expression: MatchesPattern(URL, "(?i)(union.*select|insert.*into)")
    severity: critical
    mitre: ["T1190"]
    tags: ["web", "sql-injection"]
    enabled: true

  # Directory Traversal
  - name: Directory_Traversal
    description: Path traversal attempts
    type: HTTP
    expression: MatchesPattern(URL, "\\.\\./")
    severity: high
    mitre: ["T1083"]
    tags: ["web", "path-traversal"]
    enabled: true
```

## Best Practices

### Rule Design

1.  **Be specific**: target specific behaviors rather than broad patterns.

    ```yaml
    # Good - specific
    expression: Method == "POST" && DstPort == 80 && ReqContentLength > 10000000

    # Bad - too broad
    expression: ReqContentLength > 0
    ```
2.  **Limit false positives**: add conditions until the rule matches what you mean.

    ```yaml
    # May generate false positives
    expression: DstPort == 22

    # Better - more specific
    expression: DstPort == 22 && SYN && !ACK && IsPublicIP(SrcIP)
    ```
3. **Match severity to impact**:
   * `low`: informational, minor anomalies
   * `medium`: suspicious activity that needs investigation
   * `high`: likely malicious activity
   * `critical`: active attacks that need an immediate response

### Rule Organization

1.  **Group related rules**: use a separate file per category.

    ```
    rules/
    ├── reconnaissance.yml
    ├── exfiltration.yml
    ├── malware.yml
    └── web_attacks.yml
    ```
2.  **Use descriptive names**:

    ```yaml
    # Good
    name: SSH_Bruteforce_External_Source

    # Bad
    name: Rule_1
    ```
3.  **Add tags** so you can filter and analyze alerts:

    ```yaml
    tags: ["protocol:ssh", "attack:bruteforce", "source:external"]
    ```

### Testing Rules

1.  **Test against known traffic**:

    ```bash
    # Test rule file
    net capture -read traffic.pcap -rules test_rules.yml -out test_output

    # Check generated alerts
    net dump -read test_output/Alert.ncap.gz
    ```
2.  **Watch the alert volume**:

    ```bash
    # Count alerts per rule
     net dump -read Alert.ncap.gz -json | python3 -c 'import collections,json,sys; print(collections.Counter(json.loads(line)["RuleName"] for line in sys.stdin))'
    ```
3.  **Review false positives and refine the rule**:

    ```bash
    # Review specific rule alerts
    net dump -read Alert.ncap.gz -filter "RuleName == 'SSH_Bruteforce'"
    ```

### Performance Optimization

1.  **Keep regexes simple**:

    ```yaml
    # Fast
    expression: Method == "POST"

    # Slower
    expression: MatchesPattern(Method, "^(POST|PUT|DELETE)$")
    ```
2.  **Put cheap checks first**:

    ```yaml
    # Good - fast check first
    expression: DstPort == 80 && MatchesPattern(URL, "complex_regex")

    # Suboptimal - slow check first
    expression: MatchesPattern(URL, "complex_regex") && DstPort == 80
    ```
3.  **Use helper functions**, which are native and fast:

    ```yaml
    # Prefer
    expression: IsPrivateIP(SrcIP)

    # Over
    expression: InSubnet(SrcIP, "10.0.0.0/8") || InSubnet(SrcIP, "172.16.0.0/12")
    ```

## Troubleshooting

### Rule Not Triggering

1. Check that the rule is enabled: `enabled: true`.
2. Check that the rule `type` matches the audit record type.
3. Test the expression with `-filter` on the `dump` command.
4. Check field names with the `-fields` flag.

### Too Many Alerts

1. Add conditions to make the rule more specific.
2. Raise numeric thresholds.
3. Check that the deduplication window suits the rule.

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

* Review [example rules](https://github.com/dreadl0ck/netcap/tree/v0.15.2/internal/rules/examples) for more patterns
* See [FILTERING.md](FILTERING.md) for expression syntax details
* Check the [expr-lang documentation](https://expr-lang.org/docs/language-definition)
* Explore the MITRE ATT\&CK framework at https://attack.mitre.org/
