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
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

// TestRuleValidation tests rule validation logic.
func TestRuleValidation(t *testing.T) {
	tests := []struct {
		name    string
		rule    Rule
		wantErr bool
	}{
		{
			name: "valid rule",
			rule: Rule{
				Name:       "test-rule",
				Type:       "TCP",
				Expression: "DstPort == 80",
				Action:     ActionAccept,
				Enabled:    true,
			},
			wantErr: false,
		},
		{
			name: "missing name",
			rule: Rule{
				Type:       "TCP",
				Expression: "DstPort == 80",
				Action:     ActionAccept,
			},
			wantErr: true,
		},
		{
			name: "missing type",
			rule: Rule{
				Name:       "test-rule",
				Expression: "DstPort == 80",
				Action:     ActionAccept,
			},
			wantErr: true,
		},
		{
			name: "missing expression",
			rule: Rule{
				Name:   "test-rule",
				Type:   "TCP",
				Action: ActionAccept,
			},
			wantErr: true,
		},
		{
			name: "invalid action",
			rule: Rule{
				Name:       "test-rule",
				Type:       "TCP",
				Expression: "DstPort == 80",
				Action:     Action("invalid_action"),
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.rule.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Rule.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestActionValidation tests action type validation.
func TestActionValidation(t *testing.T) {
	tests := []struct {
		action Action
		valid  bool
	}{
		{ActionAccept, true},
		{ActionDrop, true},
		{ActionModifyPayload, true},
		{ActionInjectPacket, true},
		{ActionInjectTCPRST, true},
		{ActionInjectDNS, true},
		{ActionInjectARP, true},
		{ActionDelay, true},
		{Action("unknown"), false},
		{Action(""), false},
	}

	for _, tt := range tests {
		t.Run(string(tt.action), func(t *testing.T) {
			if got := ValidateAction(tt.action); got != tt.valid {
				t.Errorf("ValidateAction(%q) = %v, want %v", tt.action, got, tt.valid)
			}
		})
	}
}

// TestLoadRulesFromFile tests rule loading from YAML.
func TestLoadRulesFromFile(t *testing.T) {
	// Create temporary rule file
	tempDir := t.TempDir()
	rulesFile := filepath.Join(tempDir, "test-rules.yml")

	rulesYAML := `
description: "Test rules"
rules:
  - name: Test Rule 1
    description: Test description
    type: TCP
    expression: DstPort == 80
    action: accept
    enabled: true
  - name: Test Rule 2
    type: DNS
    expression: "true"
    action: drop
    enabled: false
`

	if err := os.WriteFile(rulesFile, []byte(rulesYAML), 0o644); err != nil {
		t.Fatalf("Failed to write test rules file: %v", err)
	}

	config, err := LoadRulesFromFile(rulesFile)
	if err != nil {
		t.Fatalf("LoadRulesFromFile() error = %v", err)
	}

	if config.Description != "Test rules" {
		t.Errorf("Expected description 'Test rules', got '%s'", config.Description)
	}

	if len(config.Rules) != 2 {
		t.Errorf("Expected 2 rules, got %d", len(config.Rules))
	}

	// Check first rule
	if config.Rules[0].Name != "Test Rule 1" {
		t.Errorf("Expected rule name 'Test Rule 1', got '%s'", config.Rules[0].Name)
	}

	if config.Rules[0].Action != ActionAccept {
		t.Errorf("Expected action 'accept', got '%s'", config.Rules[0].Action)
	}

	// Check second rule
	if !config.Rules[0].Enabled || config.Rules[1].Enabled {
		t.Error("Rule enabled status not parsed correctly")
	}
}

// TestCompileRules tests rule compilation.
func TestCompileRules(t *testing.T) {
	config := &Config{
		Rules: []*Rule{
			{
				Name:       "valid-rule",
				Type:       "TCP",
				Expression: "DstPort == 80",
				Action:     ActionAccept,
				Enabled:    true,
			},
			{
				Name:       "disabled-rule",
				Type:       "TCP",
				Expression: "DstPort == 443",
				Action:     ActionAccept,
				Enabled:    false,
			},
		},
	}

	err := CompileRules(config)
	if err != nil {
		t.Fatalf("CompileRules() error = %v", err)
	}

	// Enabled rule should be compiled
	if config.Rules[0].compiled == nil {
		t.Error("Enabled rule should be compiled")
	}

	// Disabled rule should not be compiled
	if config.Rules[1].compiled != nil {
		t.Error("Disabled rule should not be compiled")
	}
}

// TestCompileRulesInvalidExpression tests compilation with invalid expression.
func TestCompileRulesInvalidExpression(t *testing.T) {
	config := &Config{
		Rules: []*Rule{
			{
				Name:       "invalid-rule",
				Type:       "TCP",
				Expression: "invalid syntax !!!",
				Action:     ActionAccept,
				Enabled:    true,
			},
		},
	}

	err := CompileRules(config)
	if err == nil {
		t.Error("Expected error for invalid expression, got nil")
	}
}

// TestPacketBuilder tests packet construction utilities.
func TestPacketBuilder(t *testing.T) {
	pb := NewPacketBuilder()

	srcMAC, _ := net.ParseMAC("00:11:22:33:44:55")
	dstMAC, _ := net.ParseMAC("66:77:88:99:aa:bb")
	srcIP := net.ParseIP("192.168.1.100")
	dstIP := net.ParseIP("192.168.1.1")

	t.Run("BuildTCPRSTPacket", func(t *testing.T) {
		pkt, err := pb.BuildTCPRSTPacket(srcMAC, dstMAC, srcIP, dstIP, 12345, 80, 1000, 2000)
		if err != nil {
			t.Fatalf("BuildTCPRSTPacket() error = %v", err)
		}

		if len(pkt) == 0 {
			t.Error("Expected non-empty packet")
		}

		// Decode and verify packet
		decoded := gopacket.NewPacket(pkt, layers.LayerTypeEthernet, gopacket.Default)

		ethLayer := decoded.Layer(layers.LayerTypeEthernet)
		if ethLayer == nil {
			t.Fatal("Expected Ethernet layer")
		}

		tcpLayer := decoded.Layer(layers.LayerTypeTCP)
		if tcpLayer == nil {
			t.Fatal("Expected TCP layer")
		}

		tcp := tcpLayer.(*layers.TCP)
		if !tcp.RST {
			t.Error("Expected RST flag to be set")
		}
		if !tcp.ACK {
			t.Error("Expected ACK flag to be set")
		}
	})

	t.Run("BuildTCPSYNPacket", func(t *testing.T) {
		pkt, err := pb.BuildTCPSYNPacket(srcMAC, dstMAC, srcIP, dstIP, 12345, 80, 1000)
		if err != nil {
			t.Fatalf("BuildTCPSYNPacket() error = %v", err)
		}

		decoded := gopacket.NewPacket(pkt, layers.LayerTypeEthernet, gopacket.Default)
		tcpLayer := decoded.Layer(layers.LayerTypeTCP)
		if tcpLayer == nil {
			t.Fatal("Expected TCP layer")
		}

		tcp := tcpLayer.(*layers.TCP)
		if !tcp.SYN {
			t.Error("Expected SYN flag to be set")
		}
	})

	t.Run("BuildARPRequestPacket", func(t *testing.T) {
		targetIP := net.ParseIP("192.168.1.1")
		pkt, err := pb.BuildARPRequestPacket(srcMAC, srcIP, targetIP)
		if err != nil {
			t.Fatalf("BuildARPRequestPacket() error = %v", err)
		}

		decoded := gopacket.NewPacket(pkt, layers.LayerTypeEthernet, gopacket.Default)
		arpLayer := decoded.Layer(layers.LayerTypeARP)
		if arpLayer == nil {
			t.Fatal("Expected ARP layer")
		}

		arp := arpLayer.(*layers.ARP)
		if arp.Operation != layers.ARPRequest {
			t.Errorf("Expected ARP Request, got %v", arp.Operation)
		}
	})

	t.Run("BuildARPReplyPacket", func(t *testing.T) {
		pkt, err := pb.BuildARPReplyPacket(srcMAC, dstMAC, srcIP, dstIP)
		if err != nil {
			t.Fatalf("BuildARPReplyPacket() error = %v", err)
		}

		decoded := gopacket.NewPacket(pkt, layers.LayerTypeEthernet, gopacket.Default)
		arpLayer := decoded.Layer(layers.LayerTypeARP)
		if arpLayer == nil {
			t.Fatal("Expected ARP layer")
		}

		arp := arpLayer.(*layers.ARP)
		if arp.Operation != layers.ARPReply {
			t.Errorf("Expected ARP Reply, got %v", arp.Operation)
		}
	})

	t.Run("BuildICMPEchoRequest", func(t *testing.T) {
		pkt, err := pb.BuildICMPEchoRequest(srcMAC, dstMAC, srcIP, dstIP, 1234, 1, []byte("hello"))
		if err != nil {
			t.Fatalf("BuildICMPEchoRequest() error = %v", err)
		}

		decoded := gopacket.NewPacket(pkt, layers.LayerTypeEthernet, gopacket.Default)
		icmpLayer := decoded.Layer(layers.LayerTypeICMPv4)
		if icmpLayer == nil {
			t.Fatal("Expected ICMPv4 layer")
		}

		icmp := icmpLayer.(*layers.ICMPv4)
		if icmp.TypeCode.Type() != layers.ICMPv4TypeEchoRequest {
			t.Errorf("Expected ICMP Echo Request, got %v", icmp.TypeCode.Type())
		}
	})
}

// TestDNSPacketBuilder tests DNS packet construction.
func TestDNSPacketBuilder(t *testing.T) {
	pb := NewPacketBuilder()

	srcMAC, _ := net.ParseMAC("00:11:22:33:44:55")
	dstMAC, _ := net.ParseMAC("66:77:88:99:aa:bb")
	srcIP := net.ParseIP("192.168.1.100")
	dstIP := net.ParseIP("8.8.8.8")

	t.Run("BuildDNSQueryPacket", func(t *testing.T) {
		config := DNSQueryConfig{
			SrcMAC:    srcMAC,
			DstMAC:    dstMAC,
			SrcIP:     srcIP,
			DstIP:     dstIP,
			SrcPort:   54321,
			DstPort:   53,
			QueryID:   1234,
			QueryName: "example.com",
			QueryType: layers.DNSTypeA,
		}

		pkt, err := pb.BuildDNSQueryPacket(config)
		if err != nil {
			t.Fatalf("BuildDNSQueryPacket() error = %v", err)
		}

		decoded := gopacket.NewPacket(pkt, layers.LayerTypeEthernet, gopacket.Default)
		dnsLayer := decoded.Layer(layers.LayerTypeDNS)
		if dnsLayer == nil {
			t.Fatal("Expected DNS layer")
		}

		dns := dnsLayer.(*layers.DNS)
		if dns.QR {
			t.Error("Expected DNS query (QR=false)")
		}
		if len(dns.Questions) != 1 {
			t.Errorf("Expected 1 question, got %d", len(dns.Questions))
		}
	})

	t.Run("BuildDNSResponsePacket", func(t *testing.T) {
		responseIP := net.ParseIP("192.168.1.200")
		config := DNSResponseConfig{
			SrcMAC:      dstMAC, // Swap for response
			DstMAC:      srcMAC,
			SrcIP:       dstIP,
			DstIP:       srcIP,
			SrcPort:     53,
			DstPort:     54321,
			QueryID:     1234,
			QueryName:   "example.com",
			QueryType:   layers.DNSTypeA,
			ResponseIP:  responseIP,
			ResponseTTL: 300,
		}

		pkt, err := pb.BuildDNSResponsePacket(config)
		if err != nil {
			t.Fatalf("BuildDNSResponsePacket() error = %v", err)
		}

		decoded := gopacket.NewPacket(pkt, layers.LayerTypeEthernet, gopacket.Default)
		dnsLayer := decoded.Layer(layers.LayerTypeDNS)
		if dnsLayer == nil {
			t.Fatal("Expected DNS layer")
		}

		dns := dnsLayer.(*layers.DNS)
		if !dns.QR {
			t.Error("Expected DNS response (QR=true)")
		}
		if len(dns.Answers) != 1 {
			t.Errorf("Expected 1 answer, got %d", len(dns.Answers))
		}
	})
}

// TestInjectionContext tests injection context creation.
func TestInjectionContext(t *testing.T) {
	// Build a test packet
	pb := NewPacketBuilder()
	srcMAC, _ := net.ParseMAC("00:11:22:33:44:55")
	dstMAC, _ := net.ParseMAC("66:77:88:99:aa:bb")
	srcIP := net.ParseIP("192.168.1.100")
	dstIP := net.ParseIP("192.168.1.1")

	pktData, err := pb.BuildTCPPacket(TCPPacketConfig{
		SrcMAC:  srcMAC,
		DstMAC:  dstMAC,
		SrcIP:   srcIP,
		DstIP:   dstIP,
		SrcPort: 12345,
		DstPort: 80,
		Seq:     1000,
		Ack:     2000,
		Flags:   TCPFlags{SYN: true, ACK: true},
		Payload: []byte("GET / HTTP/1.1\r\n\r\n"),
	})
	if err != nil {
		t.Fatalf("Failed to build test packet: %v", err)
	}

	pkt := gopacket.NewPacket(pktData, layers.LayerTypeEthernet, gopacket.Default)
	ctx := NewInjectionContext(pkt, "eth0")

	// Verify context fields
	if ctx.Ethernet == nil {
		t.Error("Expected Ethernet layer in context")
	}

	if ctx.IPv4 == nil {
		t.Error("Expected IPv4 layer in context")
	}

	if ctx.TCP == nil {
		t.Error("Expected TCP layer in context")
	}

	if ctx.SrcIP() != "192.168.1.100" {
		t.Errorf("Expected SrcIP 192.168.1.100, got %s", ctx.SrcIP())
	}

	if ctx.DstIP() != "192.168.1.1" {
		t.Errorf("Expected DstIP 192.168.1.1, got %s", ctx.DstIP())
	}

	if ctx.SrcPort() != 12345 {
		t.Errorf("Expected SrcPort 12345, got %d", ctx.SrcPort())
	}

	if ctx.DstPort() != 80 {
		t.Errorf("Expected DstPort 80, got %d", ctx.DstPort())
	}

	if ctx.Protocol() != "TCP" {
		t.Errorf("Expected Protocol TCP, got %s", ctx.Protocol())
	}

	if !ctx.HasTCP() {
		t.Error("Expected HasTCP() to be true")
	}

	if ctx.HasUDP() {
		t.Error("Expected HasUDP() to be false")
	}
}

// TestActionHandlers tests action handler implementations.
func TestActionHandlers(t *testing.T) {
	t.Run("GetActionHandler", func(t *testing.T) {
		// Test valid handlers
		validActions := []Action{
			ActionModifyPayload,
			ActionInjectTCPRST,
			ActionInjectDNS,
			ActionInjectARP,
			ActionDelay,
		}

		for _, action := range validActions {
			handler, err := GetActionHandler(action)
			if err != nil {
				t.Errorf("GetActionHandler(%s) unexpected error: %v", action, err)
			}
			if handler == nil {
				t.Errorf("GetActionHandler(%s) returned nil handler", action)
			}
		}

		// Test actions that don't need handlers
		handler, err := GetActionHandler(ActionAccept)
		if err != nil {
			t.Errorf("GetActionHandler(accept) unexpected error: %v", err)
		}
		if handler != nil {
			t.Error("GetActionHandler(accept) should return nil handler")
		}

		// Test invalid action
		_, err = GetActionHandler(Action("invalid"))
		if err == nil {
			t.Error("Expected error for invalid action")
		}
	})

	t.Run("DelayHandler", func(t *testing.T) {
		handler := &DelayHandler{}
		config := map[string]any{
			"delay_ms": 100,
		}

		result, err := handler.Execute(nil, config)
		if err != nil {
			t.Fatalf("DelayHandler.Execute() error = %v", err)
		}

		if !result.Success {
			t.Error("Expected success")
		}

		if result.Delay.Milliseconds() != 100 {
			t.Errorf("Expected 100ms delay, got %v", result.Delay)
		}
	})

	t.Run("ModifyPayloadHandler_Regex", func(t *testing.T) {
		handler := &ModifyPayloadHandler{}

		// Create a mock context with payload
		ctx := &InjectionContext{
			Payload: []byte("Hello World 123 Test 456"),
		}

		// Test regex replacement
		config := map[string]any{
			"search":  `\d+`,
			"replace": "NUM",
			"regex":   true,
		}

		result, err := handler.Execute(ctx, config)
		if err != nil {
			t.Fatalf("ModifyPayloadHandler.Execute() regex error = %v", err)
		}

		if !result.Success {
			t.Error("Expected success")
		}

		// Note: ModifiedPacket will be nil because we don't have network layers
		// but the logic should work
		if result.Details["regex"] != true {
			t.Error("Expected regex mode to be true")
		}
	})

	t.Run("ModifyPayloadHandler_RegexCaptureGroups", func(t *testing.T) {
		handler := &ModifyPayloadHandler{}

		ctx := &InjectionContext{
			Payload: []byte("<script>alert('xss')</script>"),
		}

		// Test regex with capture groups
		config := map[string]any{
			"search":  `<script>(.*?)</script>`,
			"replace": "<safe>$1</safe>",
			"regex":   true,
		}

		result, err := handler.Execute(ctx, config)
		if err != nil {
			t.Fatalf("ModifyPayloadHandler.Execute() capture group error = %v", err)
		}

		if !result.Success {
			t.Error("Expected success")
		}
	})

	t.Run("HTTPInjectHeaderHandler", func(t *testing.T) {
		handler := &HTTPInjectHeaderHandler{}

		ctx := &InjectionContext{
			Payload: []byte("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html></html>"),
		}

		config := map[string]any{
			"headers": map[string]any{
				"X-Injected": "test-value",
			},
		}

		result, err := handler.Execute(ctx, config)
		if err != nil {
			t.Fatalf("HTTPInjectHeaderHandler.Execute() error = %v", err)
		}

		if !result.Success {
			t.Error("Expected success")
		}

		if result.Details["modified"] != true {
			t.Error("Expected headers to be modified")
		}
	})

	t.Run("HTTPSSLStripHandler", func(t *testing.T) {
		handler := &HTTPSSLStripHandler{}

		ctx := &InjectionContext{
			Payload: []byte("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<a href=\"https://example.com\">Link</a>"),
		}

		config := map[string]any{}

		result, err := handler.Execute(ctx, config)
		if err != nil {
			t.Fatalf("HTTPSSLStripHandler.Execute() error = %v", err)
		}

		if !result.Success {
			t.Error("Expected success")
		}

		if result.Details["ssl_stripped"] != true {
			t.Error("Expected SSL to be stripped")
		}
	})

	t.Run("HTTPRedirectHandler", func(t *testing.T) {
		handler := &HTTPRedirectHandler{}

		ctx := &InjectionContext{
			Payload: []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
		}

		config := map[string]any{
			"location":    "http://evil.com/phish",
			"status_code": 302,
		}

		result, err := handler.Execute(ctx, config)
		if err != nil {
			t.Fatalf("HTTPRedirectHandler.Execute() error = %v", err)
		}

		if !result.Success {
			t.Error("Expected success")
		}

		if result.Details["location"] != "http://evil.com/phish" {
			t.Error("Expected redirect location to be set")
		}
	})
}

// TestEngineStats tests statistics tracking.
func TestEngineStats(t *testing.T) {
	stats := NewEngineStats()

	// Test initial atomic counter value
	if stats.PacketsProcessed.Load() != 0 {
		t.Error("Expected initial PacketsProcessed to be 0")
	}

	if stats.StartTime.IsZero() {
		t.Error("Expected StartTime to be set")
	}

	if stats.RuleMatches == nil {
		t.Error("Expected RuleMatches map to be initialized")
	}

	if stats.ActionCounts == nil {
		t.Error("Expected ActionCounts map to be initialized")
	}

	// Test atomic increment
	stats.PacketsProcessed.Add(5)
	if stats.PacketsProcessed.Load() != 5 {
		t.Error("Expected PacketsProcessed to be 5 after Add(5)")
	}

	stats.Errors.Add(1)
	if stats.Errors.Load() != 1 {
		t.Error("Expected Errors to be 1 after Add(1)")
	}
}

// TestNFQueueSupport tests nfqueue platform detection.
func TestNFQueueSupport(t *testing.T) {
	// This test just verifies the function doesn't panic
	supported := IsNFQueueSupported()
	t.Logf("NFQueue supported: %v", supported)
}
