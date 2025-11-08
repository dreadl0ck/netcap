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

package rules

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/dreadl0ck/netcap/types"
)

func TestLoadRulesFromFile(t *testing.T) {
	// Create a temporary rules file
	tmpDir := t.TempDir()
	rulesFile := filepath.Join(tmpDir, "test_rules.yml")

	rulesYAML := `rules:
  - name: SSH_Port_Rule
    description: Detect SSH traffic
    type: TCP
    expression: DstPort == 22
    severity: low
    mitre: ["T1021.004"]
    tags: ["ssh", "remote-access"]
    enabled: true
  
  - name: HTTP_Unusual_Port
    description: Detect HTTP on non-standard port
    type: HTTP
    expression: DstPort != 80 && DstPort != 443
    severity: medium
    mitre: ["T1071.001"]
    tags: ["http", "unusual-port"]
    enabled: true
`

	err := os.WriteFile(rulesFile, []byte(rulesYAML), 0644)
	if err != nil {
		t.Fatal(err)
	}

	// Load rules
	config, err := LoadRulesFromFile(rulesFile)
	if err != nil {
		t.Fatalf("LoadRulesFromFile() error = %v", err)
	}

	if len(config.Rules) != 2 {
		t.Errorf("Expected 2 rules, got %d", len(config.Rules))
	}

	// Verify first rule
	rule := config.Rules[0]
	if rule.Name != "SSH_Port_Rule" {
		t.Errorf("Expected rule name 'SSH_Port_Rule', got '%s'", rule.Name)
	}
	if rule.Type != "TCP" {
		t.Errorf("Expected rule type 'TCP', got '%s'", rule.Type)
	}
	if !rule.Enabled {
		t.Error("Expected rule to be enabled")
	}
}

func TestCompileRules(t *testing.T) {
	config := &Config{
		Rules: []*Rule{
			{
				Name:       "Test_Rule",
				Type:       "TCP",
				Expression: "DstPort == 443",
				Enabled:    true,
			},
		},
	}

	err := CompileRules(config)
	if err != nil {
		t.Fatalf("CompileRules() error = %v", err)
	}

	if config.Rules[0].compiled == nil {
		t.Error("Expected rule to be compiled")
	}
}

func TestEvaluateRule(t *testing.T) {
	rule := &Rule{
		Name:       "HTTPS_Traffic",
		Description: "Detect HTTPS traffic",
		Type:       "TCP",
		Expression: "DstPort == 443",
		Severity:   "low",
		Enabled:    true,
	}

	// Compile the rule first
	config := &Config{Rules: []*Rule{rule}}
	err := CompileRules(config)
	if err != nil {
		t.Fatal(err)
	}

	// Create a test TCP record
	tcp := &types.TCP{
		Timestamp: 1234567890,
		SrcPort:   12345,
		DstPort:   443,
		SrcIP:     "192.168.1.1",
		DstIP:     "8.8.8.8",
	}

	// Evaluate the rule
	alert, err := EvaluateRule(rule, tcp)
	if err != nil {
		t.Fatalf("EvaluateRule() error = %v", err)
	}

	if alert == nil {
		t.Fatal("Expected alert to be generated")
	}

	if alert.Name != "HTTPS_Traffic" {
		t.Errorf("Expected alert name 'HTTPS_Traffic', got '%s'", alert.Name)
	}
	if alert.Severity != "low" {
		t.Errorf("Expected severity 'low', got '%s'", alert.Severity)
	}
	if alert.SrcIP != "192.168.1.1" {
		t.Errorf("Expected SrcIP '192.168.1.1', got '%s'", alert.SrcIP)
	}
}

func TestParseRecordType(t *testing.T) {
	tests := []struct {
		input   string
		wantErr bool
	}{
		{"TCP", false},
		{"NC_TCP", false},
		{"HTTP", false},
		{"InvalidType", true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			_, err := parseRecordType(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseRecordType(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			}
		})
	}
}

func TestValidateSeverity(t *testing.T) {
	tests := []struct {
		severity string
		want     bool
	}{
		{"low", true},
		{"medium", true},
		{"high", true},
		{"critical", true},
		{"LOW", true},
		{"invalid", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.severity, func(t *testing.T) {
			got := ValidateSeverity(tt.severity)
			if got != tt.want {
				t.Errorf("ValidateSeverity(%q) = %v, want %v", tt.severity, got, tt.want)
			}
		})
	}
}

// MockAlertWriter is a test implementation of AlertWriter
type MockAlertWriter struct {
	alerts []*types.Alert
}

func (m *MockAlertWriter) WriteAlert(alert *types.Alert) error {
	m.alerts = append(m.alerts, alert)
	return nil
}

func (m *MockAlertWriter) Close() error {
	return nil
}

func TestEngine(t *testing.T) {
	// Create a temporary rules file
	tmpDir := t.TempDir()
	rulesFile := filepath.Join(tmpDir, "test_rules.yml")

	rulesYAML := `rules:
  - name: SSH_Traffic
    description: Detect SSH traffic
    type: TCP
    expression: DstPort == 22
    severity: low
    enabled: true
`

	err := os.WriteFile(rulesFile, []byte(rulesYAML), 0644)
	if err != nil {
		t.Fatal(err)
	}

	// Create a mock alert writer
	mockWriter := &MockAlertWriter{}

	// Create engine
	engine, err := NewEngine(rulesFile, mockWriter)
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}

	// Test TCP record that should trigger the rule
	tcp := &types.TCP{
		Timestamp: 1234567890,
		SrcPort:   12345,
		DstPort:   22,
		SrcIP:     "192.168.1.1",
		DstIP:     "10.0.0.1",
	}

	// Evaluate
	count, err := engine.Evaluate(tcp)
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}

	if count != 1 {
		t.Errorf("Expected 1 alert, got %d", count)
	}

	if len(mockWriter.alerts) != 1 {
		t.Errorf("Expected 1 alert written, got %d", len(mockWriter.alerts))
	}

	// Test deduplication - same alert should be deduplicated
	count, err = engine.Evaluate(tcp)
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}

	if count != 0 {
		t.Errorf("Expected 0 alerts (deduplicated), got %d", count)
	}
}

// TestExampleRulesCompilation tests that all example rule files compile successfully
func TestExampleRulesCompilation(t *testing.T) {
	exampleRules := []string{
		"suspicious_traffic.yml",
		"data_exfiltration.yml",
		"malware_communication.yml",
		"network_reconnaissance.yml",
		"web_attacks.yml",
		"mitre_attack_tactics.yml",
		"zeek_inspired_detections.yml",
		"threshold_detections.yml",
		"important_ports.yml",
		"industrial_ports.yml",
		"suricata_inspired_detections.yml",
		"application_detections.yml",
	}

	for _, ruleFile := range exampleRules {
		t.Run(ruleFile, func(t *testing.T) {
			// Construct path to example rules
			rulesPath := filepath.Join("examples", ruleFile)
			
			// Check if file exists
			if _, err := os.Stat(rulesPath); os.IsNotExist(err) {
				t.Skipf("Rule file does not exist: %s", rulesPath)
				return
			}

			// Load rules
			config, err := LoadRulesFromFile(rulesPath)
			if err != nil {
				t.Fatalf("Failed to load %s: %v", ruleFile, err)
			}

			// Compile rules
			err = CompileRules(config)
			if err != nil {
				t.Fatalf("Failed to compile %s: %v", ruleFile, err)
			}

			// Verify all enabled rules were compiled
			for _, rule := range config.Rules {
				if rule.Enabled {
					if rule.compiled == nil {
						t.Errorf("Rule %s in %s was not compiled", rule.Name, ruleFile)
					}
				}
			}

			t.Logf("Successfully compiled %d rules from %s", len(config.Rules), ruleFile)
		})
	}
}

// TestMITREAttackRules tests specific MITRE ATT&CK rules functionality
func TestMITREAttackRules(t *testing.T) {
	tests := []struct {
		name       string
		ruleConfig string
		record     types.AuditRecord
		shouldMatch bool
	}{
		{
			name: "RDP_Connection_Match",
			ruleConfig: `rules:
  - name: RDP_Connection
    description: Detect RDP connections
    type: TCP
    expression: DstPort == 3389
    severity: medium
    mitre: ["T1021.001"]
    enabled: true`,
			record: &types.TCP{
				Timestamp: 1234567890,
				SrcPort:   50000,
				DstPort:   3389,
				SrcIP:     "192.168.1.100",
				DstIP:     "192.168.1.50",
			},
			shouldMatch: true,
		},
		{
			name: "SMB_Admin_Share_Match",
			ruleConfig: `rules:
  - name: SMB_Admin_Share
    description: Detect SMB admin share access
    type: TCP
    expression: DstPort == 445 && SYN && !RST
    severity: high
    mitre: ["T1021.002"]
    enabled: true`,
			record: &types.TCP{
				Timestamp: 1234567890,
				SrcPort:   50000,
				DstPort:   445,
				SYN:       true,
				RST:       false,
				SrcIP:     "192.168.1.100",
				DstIP:     "192.168.1.50",
			},
			shouldMatch: true,
		},
		{
			name: "WinRM_Connection_Match",
			ruleConfig: `rules:
  - name: WinRM_Connection
    description: Detect WinRM connections
    type: TCP
    expression: DstPort == 5985 || DstPort == 5986
    severity: high
    mitre: ["T1021.006"]
    enabled: true`,
			record: &types.TCP{
				Timestamp: 1234567890,
				SrcPort:   50000,
				DstPort:   5985,
				SrcIP:     "192.168.1.100",
				DstIP:     "192.168.1.50",
			},
			shouldMatch: true,
		},
		{
			name: "LDAP_Replication_Match",
			ruleConfig: `rules:
  - name: LDAP_Replication
    description: Detect LDAP replication
    type: TCP
    expression: DstPort == 389 && SYN
    severity: high
    mitre: ["T1003.006"]
    enabled: true`,
			record: &types.TCP{
				Timestamp: 1234567890,
				SrcPort:   50000,
				DstPort:   389,
				SYN:       true,
				SrcIP:     "192.168.1.100",
				DstIP:     "192.168.1.10",
			},
			shouldMatch: true,
		},
		{
			name: "Kerberos_Activity_Match",
			ruleConfig: `rules:
  - name: Kerberos_Activity
    description: Detect Kerberos traffic
    type: TCP
    expression: DstPort == 88
    severity: medium
    mitre: ["T1558.001"]
    enabled: true`,
			record: &types.TCP{
				Timestamp: 1234567890,
				SrcPort:   50000,
				DstPort:   88,
				SrcIP:     "192.168.1.100",
				DstIP:     "192.168.1.10",
			},
			shouldMatch: true,
		},
		{
			name: "DNS_Zone_Transfer_Match",
			ruleConfig: `rules:
  - name: DNS_Zone_Transfer
    description: Detect DNS AXFR queries
    type: DNS
    expression: len(Questions) > 0 && Questions[0].Type == 252
    severity: high
    mitre: ["T1590.002"]
    enabled: true`,
			record: &types.DNS{
				Timestamp: 1234567890,
				SrcIP:     "192.168.1.100",
				DstIP:     "8.8.8.8",
				Questions: []*types.DNSQuestion{
					{Type: 252, Name: "example.com"},
				},
			},
			shouldMatch: true,
		},
		{
			name: "HTTP_C2_Beaconing_Match",
			ruleConfig: `rules:
  - name: HTTP_C2_Beaconing
    description: Detect HTTP beaconing
    type: HTTP
    expression: Method == "POST" && Host != ""
    severity: medium
    mitre: ["T1071.001"]
    enabled: true`,
			record: &types.HTTP{
				Timestamp: 1234567890,
				SrcIP:     "192.168.1.100",
				DstIP:     "10.20.30.40",
				Method:    "POST",
				Host:      "example.com",
			},
			shouldMatch: true,
		},
		{
			name: "No_Match_Wrong_Port",
			ruleConfig: `rules:
  - name: RDP_Connection
    description: Detect RDP connections
    type: TCP
    expression: DstPort == 3389
    severity: medium
    mitre: ["T1021.001"]
    enabled: true`,
			record: &types.TCP{
				Timestamp: 1234567890,
				SrcPort:   50000,
				DstPort:   80,  // Wrong port
				SrcIP:     "192.168.1.100",
				DstIP:     "192.168.1.50",
			},
			shouldMatch: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create temporary rules file
			tmpDir := t.TempDir()
			rulesFile := filepath.Join(tmpDir, "test_rules.yml")
			
			err := os.WriteFile(rulesFile, []byte(tt.ruleConfig), 0644)
			if err != nil {
				t.Fatal(err)
			}

			// Load and compile rules
			config, err := LoadRulesFromFile(rulesFile)
			if err != nil {
				t.Fatalf("LoadRulesFromFile() error = %v", err)
			}

			err = CompileRules(config)
			if err != nil {
				t.Fatalf("CompileRules() error = %v", err)
			}

			// Evaluate rule
			alert, err := EvaluateRule(config.Rules[0], tt.record)
			if err != nil {
				t.Fatalf("EvaluateRule() error = %v", err)
			}

			if tt.shouldMatch && alert == nil {
				t.Error("Expected rule to match, but got no alert")
			}

			if !tt.shouldMatch && alert != nil {
				t.Error("Expected rule not to match, but got alert")
			}

			// Verify alert fields if match expected
			if tt.shouldMatch && alert != nil {
				if len(alert.MITRE) == 0 {
					t.Error("Alert missing MITRE ATT&CK technique ID")
				}
				if alert.Severity == "" {
					t.Error("Alert missing severity")
				}
			}
		})
	}
}

// TestRuleSeverityValidation tests that all example rules have valid severity levels
func TestRuleSeverityValidation(t *testing.T) {
	exampleRules := []string{
		"suspicious_traffic.yml",
		"data_exfiltration.yml",
		"malware_communication.yml",
		"network_reconnaissance.yml",
		"web_attacks.yml",
		"mitre_attack_tactics.yml",
		"zeek_inspired_detections.yml",
		"suricata_inspired_detections.yml",
	}

	for _, ruleFile := range exampleRules {
		t.Run(ruleFile, func(t *testing.T) {
			rulesPath := filepath.Join("examples", ruleFile)
			
			if _, err := os.Stat(rulesPath); os.IsNotExist(err) {
				t.Skipf("Rule file does not exist: %s", rulesPath)
				return
			}

			config, err := LoadRulesFromFile(rulesPath)
			if err != nil {
				t.Fatalf("Failed to load %s: %v", ruleFile, err)
			}

			for _, rule := range config.Rules {
				if rule.Severity != "" && !ValidateSeverity(rule.Severity) {
					t.Errorf("Rule %s has invalid severity: %s", rule.Name, rule.Severity)
				}
			}
		})
	}
}

// TestRuleMITREFields tests that MITRE ATT&CK rules have proper MITRE technique IDs
func TestRuleMITREFields(t *testing.T) {
	rulesPath := filepath.Join("examples", "mitre_attack_tactics.yml")
	
	if _, err := os.Stat(rulesPath); os.IsNotExist(err) {
		t.Skip("mitre_attack_tactics.yml does not exist")
		return
	}

	config, err := LoadRulesFromFile(rulesPath)
	if err != nil {
		t.Fatalf("Failed to load mitre_attack_tactics.yml: %v", err)
	}

	for _, rule := range config.Rules {
		if len(rule.MITRE) == 0 {
			t.Errorf("Rule %s is missing MITRE ATT&CK technique IDs", rule.Name)
		}

		// Verify MITRE technique ID format (e.g., T1021.001)
		for _, mitreID := range rule.MITRE {
			if len(mitreID) < 5 || mitreID[0] != 'T' {
				t.Errorf("Rule %s has invalid MITRE technique ID: %s", rule.Name, mitreID)
			}
		}
	}
}

// TestZeekInspiredRules tests specific Zeek-inspired detection rules
func TestZeekInspiredRules(t *testing.T) {
	tests := []struct {
		name       string
		ruleConfig string
		record     types.AuditRecord
		shouldMatch bool
	}{
		{
			name: "SQL_Injection_Detection",
			ruleConfig: `rules:
  - name: SQL_Injection_Test
    description: Detect SQL injection
    type: HTTP
    expression: MatchesPattern(URL, "(?i)union.*select")
    severity: critical
    enabled: true`,
			record: &types.HTTP{
				Timestamp: 1234567890,
				SrcIP:     "192.168.1.100",
				DstIP:     "10.20.30.40",
				Method:    "GET",
				URL:       "/api/users?id=1 UNION SELECT password FROM users",
			},
			shouldMatch: true,
		},
		{
			name: "Telnet_Detection",
			ruleConfig: `rules:
  - name: Telnet_Usage
    description: Detect Telnet usage
    type: TCP
    expression: DstPort == 23
    severity: high
    enabled: true`,
			record: &types.TCP{
				Timestamp: 1234567890,
				SrcPort:   50000,
				DstPort:   23,
				SrcIP:     "192.168.1.100",
				DstIP:     "192.168.1.50",
			},
			shouldMatch: true,
		},
		{
			name: "DHCP_Rogue_Server",
			ruleConfig: `rules:
  - name: DHCP_Server_Detection
    description: Detect DHCP server
    type: UDP
    expression: SrcPort == 67 && DstPort == 68
    severity: high
    enabled: true`,
			record: &types.UDP{
				Timestamp: 1234567890,
				SrcPort:   67,
				DstPort:   68,
				SrcIP:     "192.168.1.1",
				DstIP:     "192.168.1.100",
			},
			shouldMatch: true,
		},
		{
			name: "WPAD_DNS_Query",
			ruleConfig: `rules:
  - name: WPAD_Detection
    description: Detect WPAD queries
    type: DNS
    expression: len(Questions) > 0 && MatchesPattern(Questions[0].Name, "(?i)wpad")
    severity: medium
    enabled: true`,
			record: &types.DNS{
				Timestamp: 1234567890,
				SrcIP:     "192.168.1.100",
				DstIP:     "8.8.8.8",
				Questions: []*types.DNSQuestion{
					{Type: 1, Name: "wpad.example.com"},
				},
			},
			shouldMatch: true,
		},
		{
			name: "HTTP_Scanner_UserAgent",
			ruleConfig: `rules:
  - name: Scanner_Detection
    description: Detect scanner user agents
    type: HTTP
    expression: MatchesPattern(UserAgent, "(?i)nikto")
    severity: high
    enabled: true`,
			record: &types.HTTP{
				Timestamp: 1234567890,
				SrcIP:     "192.168.1.100",
				DstIP:     "10.20.30.40",
				Method:    "GET",
				URL:       "/admin",
				UserAgent: "Nikto/2.1.6",
			},
			shouldMatch: true,
		},
		{
			name: "MySQL_External_Access",
			ruleConfig: `rules:
  - name: MySQL_External
    description: Detect MySQL external access
    type: TCP
    expression: DstPort == 3306 && IsPublicIP(DstIP)
    severity: high
    enabled: true`,
			record: &types.TCP{
				Timestamp: 1234567890,
				SrcPort:   50000,
				DstPort:   3306,
				SrcIP:     "192.168.1.100",
				DstIP:     "8.8.8.8",
			},
			shouldMatch: true,
		},
		{
			name: "Docker_Daemon_Access",
			ruleConfig: `rules:
  - name: Docker_Daemon
    description: Detect Docker daemon access
    type: TCP
    expression: DstPort == 2375
    severity: high
    enabled: true`,
			record: &types.TCP{
				Timestamp: 1234567890,
				SrcPort:   50000,
				DstPort:   2375,
				SrcIP:     "192.168.1.100",
				DstIP:     "192.168.1.50",
			},
			shouldMatch: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			rulesFile := filepath.Join(tmpDir, "test_rules.yml")
			
			err := os.WriteFile(rulesFile, []byte(tt.ruleConfig), 0644)
			if err != nil {
				t.Fatal(err)
			}

			config, err := LoadRulesFromFile(rulesFile)
			if err != nil {
				t.Fatalf("LoadRulesFromFile() error = %v", err)
			}

			err = CompileRules(config)
			if err != nil {
				t.Fatalf("CompileRules() error = %v", err)
			}

			alert, err := EvaluateRule(config.Rules[0], tt.record)
			if err != nil {
				t.Fatalf("EvaluateRule() error = %v", err)
			}

			if tt.shouldMatch && alert == nil {
				t.Error("Expected rule to match, but got no alert")
			}

			if !tt.shouldMatch && alert != nil {
				t.Error("Expected rule not to match, but got alert")
			}
		})
	}
}

// TestRuleNameUniqueness tests that rule names are unique within each file
func TestRuleNameUniqueness(t *testing.T) {
	exampleRules := []string{
		"suspicious_traffic.yml",
		"data_exfiltration.yml",
		"malware_communication.yml",
		"network_reconnaissance.yml",
		"web_attacks.yml",
		"mitre_attack_tactics.yml",
		"zeek_inspired_detections.yml",
		"threshold_detections.yml",
		"important_ports.yml",
		"industrial_ports.yml",
		"suricata_inspired_detections.yml",
	}

	for _, ruleFile := range exampleRules {
		t.Run(ruleFile, func(t *testing.T) {
			rulesPath := filepath.Join("examples", ruleFile)
			
			if _, err := os.Stat(rulesPath); os.IsNotExist(err) {
				t.Skipf("Rule file does not exist: %s", rulesPath)
				return
			}

			config, err := LoadRulesFromFile(rulesPath)
			if err != nil {
				t.Fatalf("Failed to load %s: %v", ruleFile, err)
			}

			namesSeen := make(map[string]bool)
			for _, rule := range config.Rules {
				if namesSeen[rule.Name] {
					t.Errorf("Duplicate rule name found in %s: %s", ruleFile, rule.Name)
				}
				namesSeen[rule.Name] = true
			}
		})
	}
}

// TestThresholdAlerts tests that threshold-based alerting works correctly
func TestThresholdAlerts(t *testing.T) {
	// Create a temporary rules file with a threshold rule
	tmpDir := t.TempDir()
	rulesFile := filepath.Join(tmpDir, "test_threshold_rules.yml")

	rulesYAML := `rules:
  - name: SSH_Brute_Force
    description: Detect SSH brute force with threshold
    type: TCP
    expression: DstPort == 22 && SYN && !ACK
    severity: high
    enabled: true
    threshold: 5
    threshold_window: 60
`

	err := os.WriteFile(rulesFile, []byte(rulesYAML), 0644)
	if err != nil {
		t.Fatal(err)
	}

	// Create a mock alert writer
	mockWriter := &MockAlertWriter{}

	// Create engine
	engine, err := NewEngine(rulesFile, mockWriter)
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}

	// Create a test TCP record
	tcp := &types.TCP{
		Timestamp: 1234567890,
		SrcPort:   12345,
		DstPort:   22,
		SrcIP:     "192.168.1.100",
		DstIP:     "10.0.0.1",
		SYN:       true,
		ACK:       false,
	}

	// Test that first 4 matches don't trigger an alert (threshold is 5)
	for i := 0; i < 4; i++ {
		count, err := engine.Evaluate(tcp)
		if err != nil {
			t.Fatalf("Evaluate() error = %v (iteration %d)", err, i+1)
		}
		if count != 0 {
			t.Errorf("Expected 0 alerts before threshold reached (iteration %d), got %d", i+1, count)
		}
	}

	// 5th match should trigger the alert
	count, err := engine.Evaluate(tcp)
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if count != 1 {
		t.Errorf("Expected 1 alert when threshold reached, got %d", count)
	}
	if len(mockWriter.alerts) != 1 {
		t.Errorf("Expected 1 alert written, got %d", len(mockWriter.alerts))
	}

	// Verify alert properties
	if len(mockWriter.alerts) > 0 {
		alert := mockWriter.alerts[0]
		if alert.RuleName != "SSH_Brute_Force" {
			t.Errorf("Expected alert rule name 'SSH_Brute_Force', got '%s'", alert.RuleName)
		}
		if alert.Severity != "high" {
			t.Errorf("Expected alert severity 'high', got '%s'", alert.Severity)
		}
	}

	// After threshold is reached and alert is triggered, counter should reset
	// Reset mock writer to test fresh threshold cycle
	mockWriter.alerts = nil
	
	// Change source IP to avoid deduplication of the actual alert
	tcp.SrcIP = "192.168.1.101"
	
	// Test that next 4 matches don't trigger (need 5 total again)
	for i := 0; i < 4; i++ {
		tcp.SrcPort = int32(12346 + i) // Vary source port for uniqueness
		count, err := engine.Evaluate(tcp)
		if err != nil {
			t.Fatalf("Evaluate() error = %v (iteration %d)", err, i+1)
		}
		if count != 0 {
			t.Errorf("Expected 0 alerts in second cycle before threshold (iteration %d), got %d", i+1, count)
		}
	}

	// 5th match in second cycle should trigger the alert again
	tcp.SrcPort = int32(12350)
	count, err = engine.Evaluate(tcp)
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if count != 1 {
		t.Errorf("Expected 1 alert when threshold reached in second cycle, got %d", count)
	}
	if len(mockWriter.alerts) != 1 {
		t.Errorf("Expected 1 alert in second cycle, got %d", len(mockWriter.alerts))
	}
}

// TestThresholdWithoutConfig tests that rules without threshold config work as before (immediate alert)
func TestThresholdWithoutConfig(t *testing.T) {
	// Create a temporary rules file without threshold
	tmpDir := t.TempDir()
	rulesFile := filepath.Join(tmpDir, "test_no_threshold_rules.yml")

	rulesYAML := `rules:
  - name: SSH_Traffic
    description: Detect SSH traffic immediately
    type: TCP
    expression: DstPort == 22
    severity: low
    enabled: true
`

	err := os.WriteFile(rulesFile, []byte(rulesYAML), 0644)
	if err != nil {
		t.Fatal(err)
	}

	// Create a mock alert writer
	mockWriter := &MockAlertWriter{}

	// Create engine
	engine, err := NewEngine(rulesFile, mockWriter)
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}

	// Create a test TCP record
	tcp := &types.TCP{
		Timestamp: 1234567890,
		SrcPort:   12345,
		DstPort:   22,
		SrcIP:     "192.168.1.100",
		DstIP:     "10.0.0.1",
	}

	// First match should immediately trigger alert (no threshold)
	count, err := engine.Evaluate(tcp)
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if count != 1 {
		t.Errorf("Expected 1 alert immediately (no threshold), got %d", count)
	}
	if len(mockWriter.alerts) != 1 {
		t.Errorf("Expected 1 alert written, got %d", len(mockWriter.alerts))
	}
}

// TestSQLInjectionRule tests the SQL Injection detection rule with various attack patterns
func TestSQLInjectionRule(t *testing.T) {
	// Rule configuration using single quotes in YAML to avoid double-escaping issues
	ruleConfig := `rules:
  - name: SQL Injection Attempt
    description: Detect potential SQL injection in HTTP requests using common patterns
    type: HTTP
    expression: 'MatchesPattern(URL, "(?i)(union.*select|insert.*into|''.*or.*''|\".*or.*\"|;.*drop|exec.*xp_cmdshell|delete.*from|drop.*table)")'
    severity: critical
    mitre: ["T1190"]
    tags: ["web", "sql-injection", "injection", "sqli", "http", "web-attack"]
    enabled: true
`

	tests := []struct {
		name        string
		url         string
		shouldMatch bool
		description string
	}{
		{
			name:        "Union_Select_Attack",
			url:         "/api/users?id=1 UNION SELECT password FROM users",
			shouldMatch: true,
			description: "Classic UNION SELECT injection",
		},
		{
			name:        "Union_Select_Lowercase",
			url:         "/api/data?id=1 union select * from admin",
			shouldMatch: true,
			description: "Lowercase union select",
		},
		{
			name:        "Insert_Into_Attack",
			url:         "/register?name=test&email=test@test.com'); INSERT INTO users VALUES ('admin','password",
			shouldMatch: true,
			description: "INSERT INTO injection",
		},
		{
			name:        "Single_Quote_Or_Attack",
			url:         "/login?user=admin' OR '1'='1",
			shouldMatch: true,
			description: "Classic single quote OR injection",
		},
		{
			name:        "Double_Quote_Or_Attack",
			url:         "/login?user=admin\" OR \"1\"=\"1",
			shouldMatch: true,
			description: "Double quote OR injection",
		},
		{
			name:        "Drop_Table_Attack",
			url:         "/api/delete?id=1; DROP TABLE users",
			shouldMatch: true,
			description: "DROP TABLE injection",
		},
		{
			name:        "Drop_Table_Lowercase",
			url:         "/api/delete?id=1; drop table logs--",
			shouldMatch: true,
			description: "Lowercase drop table",
		},
		{
			name:        "XP_Cmdshell_Attack",
			url:         "/search?q=test'; EXEC xp_cmdshell 'dir'--",
			shouldMatch: true,
			description: "SQL Server xp_cmdshell injection",
		},
		{
			name:        "Delete_From_Attack",
			url:         "/api/remove?id=1'; DELETE FROM users WHERE '1'='1",
			shouldMatch: true,
			description: "DELETE FROM injection",
		},
		{
			name:        "Legitimate_URL_1",
			url:         "/api/users/123",
			shouldMatch: false,
			description: "Normal API endpoint",
		},
		{
			name:        "Legitimate_URL_2",
			url:         "/search?q=how+to+select+items",
			shouldMatch: false,
			description: "Search query with word 'select'",
		},
		{
			name:        "Legitimate_URL_3",
			url:         "/products?category=electronics",
			shouldMatch: false,
			description: "Normal product query",
		},
		{
			name:        "Legitimate_URL_4",
			url:         "/api/table/list",
			shouldMatch: false,
			description: "URL containing 'table' but not injection",
		},
		{
			name:        "Legitimate_URL_With_Quotes",
			url:         "/search?q=\"laptop\"",
			shouldMatch: false,
			description: "Search with quotes but no OR pattern",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create temporary rules file
			tmpDir := t.TempDir()
			rulesFile := filepath.Join(tmpDir, "sql_injection_test.yml")
			
			err := os.WriteFile(rulesFile, []byte(ruleConfig), 0644)
			if err != nil {
				t.Fatal(err)
			}

			// Load and compile rules
			config, err := LoadRulesFromFile(rulesFile)
			if err != nil {
				t.Fatalf("LoadRulesFromFile() error = %v", err)
			}

			err = CompileRules(config)
			if err != nil {
				t.Fatalf("CompileRules() error = %v", err)
			}

			// Create HTTP record with the test URL
			httpRecord := &types.HTTP{
				Timestamp: 1234567890,
				SrcIP:     "192.168.1.100",
				DstIP:     "10.20.30.40",
				Method:    "GET",
				Host:      "example.com",
				URL:       tt.url,
			}

			// Evaluate rule
			alert, err := EvaluateRule(config.Rules[0], httpRecord)
			if err != nil {
				t.Fatalf("EvaluateRule() error = %v", err)
			}

			// Check if result matches expectation
			if tt.shouldMatch && alert == nil {
				t.Errorf("Expected SQL injection detection for: %s\nURL: %s", tt.description, tt.url)
			}

			if !tt.shouldMatch && alert != nil {
				t.Errorf("False positive - SQL injection detected for legitimate URL: %s\nURL: %s", tt.description, tt.url)
			}

			// If match expected, verify alert properties
			if tt.shouldMatch && alert != nil {
				if alert.Severity != "critical" {
					t.Errorf("Expected severity 'critical', got '%s'", alert.Severity)
				}
				if alert.RuleName != "SQL Injection Attempt" {
					t.Errorf("Expected rule name 'SQL Injection Attempt', got '%s'", alert.RuleName)
				}
				if len(alert.MITRE) == 0 {
					t.Error("Expected MITRE ATT&CK technique ID")
				}
				if len(alert.Tags) == 0 {
					t.Error("Expected tags to be populated")
				}
			}
		})
	}
}

// TestSQLInjectionRuleCompilation specifically tests that the SQL injection rule compiles without errors
func TestSQLInjectionRuleCompilation(t *testing.T) {
	// Test the exact rule configuration from web_attacks.yml
	ruleConfig := `rules:
  - name: SQL Injection Attempt
    description: Detect potential SQL injection in HTTP requests using common patterns
    type: HTTP
    expression: 'MatchesPattern(URL, "(?i)(union.*select|insert.*into|''.*or.*''|\".*or.*\"|;.*drop|exec.*xp_cmdshell|delete.*from|drop.*table)")'
    severity: critical
    mitre: ["T1190"]
    tags: ["web", "sql-injection", "injection", "sqli", "http", "web-attack"]
    enabled: true
`

	tmpDir := t.TempDir()
	rulesFile := filepath.Join(tmpDir, "sql_injection_compile_test.yml")
	
	err := os.WriteFile(rulesFile, []byte(ruleConfig), 0644)
	if err != nil {
		t.Fatal(err)
	}

	// Load rules
	config, err := LoadRulesFromFile(rulesFile)
	if err != nil {
		t.Fatalf("LoadRulesFromFile() error = %v", err)
	}

	// Compile rules - this is where the original error occurred
	err = CompileRules(config)
	if err != nil {
		t.Fatalf("CompileRules() failed - rule did not compile: %v", err)
	}

	// Verify the rule was compiled successfully
	if len(config.Rules) != 1 {
		t.Fatalf("Expected 1 rule, got %d", len(config.Rules))
	}

	rule := config.Rules[0]
	if rule.compiled == nil {
		t.Fatal("Rule was not compiled (compiled field is nil)")
	}

	t.Log("SQL Injection rule compiled successfully")
}

