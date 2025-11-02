<!-- 587f34d7-7b78-44f2-9b1a-3b86941d20af 9cfdb345-2de9-4a9e-bfaf-b68cef35f3c2 -->
# Expr-lang Filtering & Rules Engine Implementation

## Overview

Integrate [expr-lang](https://expr-lang.org) to enable expression-based filtering of audit records and rule-based alerting. Support filtering during both capture (live/pcap) and dump operations. Implement a rules engine that evaluates expressions against audit records and generates alerts.

## Implementation Steps

### 1. Add Dependencies

- Add `github.com/expr-lang/expr` to `go.mod`
- Run `go get github.com/expr-lang/expr@latest`

### 2. Create Filter Package (`filter/`)

Create a new package to handle expression compilation and evaluation:

**`filter/filter.go`**

- `CompileExpression(expr string, recordType types.Type) (*vm.Program, error)` - compiles an expression for a specific audit record type
- `EvaluateExpression(program *vm.Program, record types.AuditRecord) (bool, error)` - evaluates a compiled expression against an audit record
- `CreateEnvironment(record types.AuditRecord) map[string]interface{}` - creates the expression environment from an audit record

**`filter/helpers.go`**

Network helper functions for expressions:

- `InSubnet(ip, cidr string) bool` - check if IP is in subnet
- `IsPrivateIP(ip string) bool` - check if IP is private
- `IsPublicIP(ip string) bool` - check if IP is public
- `ParsePort(port string) int` - parse port number
- `PortInRange(port, start, end int) bool` - check if port in range

Time helper functions:

- `TimeInRange(ts, start, end int64) bool` - check if timestamp in range
- `DurationSince(ts int64) int64` - duration since timestamp
- `FormatTime(ts int64, format string) string` - format timestamp

String helper functions:

- `ContainsAny(str string, substrs []string) bool` - check if string contains any substring
- `MatchesPattern(str, pattern string) bool` - regex pattern matching

**`filter/filter_test.go`**

- Test expression compilation for different audit record types
- Test field access (nested fields, arrays, maps)
- Test helper functions
- Test error handling (invalid expressions, type mismatches)

### 3. Extend Dump Command

**`cmd/dump/flags.go`**

- Add `-filter` flag for expression-based filtering
- Example: `-filter "SrcIP == '192.168.1.1' && DstPort == 443"`

**`cmd/dump/main.go`**

- Compile filter expression before dumping (if provided)
- Pass compiled program to `io.Dump`

**`io/utils.go`** - Update `Dump()` function

- Add `FilterProgram *vm.Program` field to `DumpConfig`
- After reading each record, evaluate filter expression
- Only output records that match the filter (return true)
- Count filtered vs total records and display summary

### 4. Create Rules Engine Package (`rules/`)

**`rules/rule.go`**

Replace existing `rule/rule.go` with comprehensive implementation:

- `Rule` struct with fields:
    - `Name string` - unique rule identifier
    - `Description string` - human-readable description
    - `Type types.Type` - audit record type to apply to
    - `Expression string` - expr-lang expression
    - `Severity string` - alert severity (low, medium, high, critical)
    - `MITRE []string` - MITRE ATT&CK IDs
    - `Tags []string` - custom tags
    - `Enabled bool` - whether rule is active
- `Config` struct for rule configuration with `Rules []*Rule`
- `LoadRulesFromFile(path string) (*Config, error)` - load rules from YAML
- `CompileRules(config *Config) error` - compile all rule expressions
- `EvaluateRule(rule *Rule, record types.AuditRecord) (*types.Alert, error)` - evaluate rule and create alert if matched

**`rules/engine.go`**

- `Engine` struct managing rules and alert generation
- `NewEngine(rulesPath string, alertWriter AlertWriter) (*Engine, error)` - create engine with rules
- `Evaluate(record types.AuditRecord) error` - evaluate all applicable rules for a record
- `WriteAlert(alert *types.Alert) error` - write alert as audit record
- Alert deduplication within time window
- Alert rate limiting per rule

**`rules/alert_writer.go`**

- `AlertWriter` interface for writing alerts
- `FileAlertWriter` implementation using netcap audit record writer
- Writes alerts to `Alert.ncap.gz` in output directory

**`rules/examples/`**

Create example rule files:

**`suspicious_traffic.yml`**:

```yaml
rules:
  - name: SSH_Bruteforce
    description: Detect multiple failed SSH connections
    type: TCP
    expression: DstPort == 22 && count > 10
    severity: high
    mitre: ["T1110"]
    enabled: true
    
  - name: DNS_Tunneling
    description: Detect suspiciously large DNS queries
    type: DNS
    expression: len(Questions[0].Name) > 100
    severity: medium
    mitre: ["T1071.004"]
    enabled: true
```

**`rules_test.go`**

- Test rule loading from YAML
- Test rule compilation
- Test rule evaluation with mock audit records
- Test alert generation
- Test deduplication

### 5. Extend Capture Command

**`cmd/capture/flags.go`**

- Add `-filter` flag for expression filtering
- Add `-rules` flag for rules file path
- Add `-alert-output` flag for alert file output location (defaults to output dir)

**`cmd/capture/main.go`**

- Load filter expression (if provided)
- Load rules engine (if rules file provided)
- Pass filter and rules engine to collector

**`collector/collector.go`**

- Add `filterProgram *vm.Program` field
- Add `rulesEngine *rules.Engine` field
- Modify `NewCollector()` to accept filter and rules engine

**`collector/worker.go`** (or relevant file handling audit record writes)

- Before writing audit record, evaluate filter expression (if set)
- Skip writing if filter returns false
- Evaluate rules engine for all records (even if filtered out)
- Rules engine writes alerts independently

### 6. Update Alert Protobuf (if needed)

Check `netcap.proto` Alert message and enhance if necessary:

- Ensure it has: `RuleName`, `RecordType`, `MatchedRecord` (JSON), `Context` fields
- Regenerate protobuf with `protoc` if modified

### 7. Documentation

**`docs/FILTERING.md`**

- Expression syntax overview
- Available fields per audit record type
- Helper functions reference
- Filter examples for common use cases
- Performance considerations

**`docs/RULES_ENGINE.md`**

- Rules engine architecture
- Rule configuration format (YAML schema)
- Writing effective rules
- MITRE ATT&CK integration
- Alert structure and handling
- Example rules for common attacks

**`docs/examples/filters/`**

Create example filter expressions:

- `http_specific_host.txt`: `Type == "HTTP" && Host == "example.com"`
- `suspicious_ports.txt`: `(DstPort > 49152) || (DstPort == 31337)`
- `large_payloads.txt`: `PayloadSize > 10000`
- `private_to_public.txt`: `IsPrivateIP(SrcIP) && IsPublicIP(DstIP)`

**`docs/examples/rules/`**

- `network_reconnaissance.yml` - port scanning, network mapping
- `data_exfiltration.yml` - large uploads, suspicious protocols
- `malware_communication.yml` - C2 traffic patterns
- `web_attacks.yml` - SQL injection, XSS attempts

### 8. Testing

**Integration Tests**

- `filter/integration_test.go` - test filtering with real audit record files
- `rules/integration_test.go` - test rules engine with pcap processing
- Create test fixtures in `tests/fixtures/` with known patterns

**CLI Tests**

- Test `net dump -read <file> -filter "<expr>"`
- Test `net capture -read <pcap> -filter "<expr>"`
- Test `net capture -read <pcap> -rules <rules.yml>`
- Verify alert files are created with correct content

### 9. Update Build System

**`zeus/commands.yml`**

- Add commands for running filter tests
- Add commands for validating rule files
- Update install target to ensure expr dependency is included

## Key Files to Modify

- `go.mod` - add expr-lang dependency
- `cmd/dump/flags.go`, `cmd/dump/main.go` - filter flag
- `cmd/capture/flags.go`, `cmd/capture/main.go` - filter & rules flags  
- `io/utils.go` - integrate filtering in Dump()
- `collector/collector.go`, `collector/worker.go` - filtering & rules in capture
- `netcap.proto` (if Alert needs enhancement)

## Key Files to Create

- `filter/filter.go`, `filter/helpers.go`, `filter/filter_test.go`
- `rules/rule.go`, `rules/engine.go`, `rules/alert_writer.go`, `rules/rules_test.go`
- `rules/examples/*.yml`
- `docs/FILTERING.md`, `docs/RULES_ENGINE.md`
- `docs/examples/filters/*.txt`, `docs/examples/rules/*.yml`

## Success Criteria

1. Can filter audit records during dump: `net dump -read TCP.ncap.gz -filter "DstPort == 443"`
2. Can filter during capture: `net capture -read traffic.pcap -filter "IsPrivateIP(SrcIP)"`
3. Can apply rules during capture: `net capture -read traffic.pcap -rules security.yml`
4. Alerts written to `Alert.ncap.gz` with full context
5. Comprehensive documentation with working examples
6. All tests passing

### To-dos

- [ ] Add github.com/expr-lang/expr dependency to go.mod
- [ ] Create filter package with expression compilation, evaluation, and helper functions
- [ ] Add -filter flag to dump command and integrate expression evaluation
- [ ] Create rules engine package with rule loading, compilation, evaluation, and alert generation
- [ ] Add -filter and -rules flags to capture command and integrate into collector
- [ ] Create example YAML rule files for common attack patterns
- [ ] Write comprehensive documentation for filtering and rules engine with examples
- [ ] Write unit and integration tests for filter and rules packages
- [ ] End-to-end testing of filtering and rules with real pcap files