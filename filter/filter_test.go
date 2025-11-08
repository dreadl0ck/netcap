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

package filter

import (
	"testing"

	"github.com/dreadl0ck/netcap/types"
)

func TestCompileExpression(t *testing.T) {
	tests := []struct {
		name       string
		expression string
		recordType types.Type
		wantErr    bool
	}{
		{
			name:       "simple comparison",
			expression: "DstPort == 443",
			recordType: types.Type_NC_TCP,
			wantErr:    false,
		},
		{
			name:       "logical AND",
			expression: "SrcPort == 80 && DstPort == 443",
			recordType: types.Type_NC_TCP,
			wantErr:    false,
		},
		{
			name:       "helper function",
			expression: "IsPrivateIP(SrcIP)",
			recordType: types.Type_NC_IPv4,
			wantErr:    false,
		},
		{
			name:       "empty expression",
			expression: "",
			recordType: types.Type_NC_TCP,
			wantErr:    true,
		},
		{
			name:       "invalid syntax",
			expression: "DstPort = 443",
			recordType: types.Type_NC_TCP,
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := CompileExpression(tt.expression, tt.recordType)
			if (err != nil) != tt.wantErr {
				t.Errorf("CompileExpression() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestEvaluateExpression_TCP(t *testing.T) {
	// Create a test TCP record
	tcp := &types.TCP{
		Timestamp: 1234567890,
		SrcPort:   80,
		DstPort:   443,
		SrcIP:     "192.168.1.1",
		DstIP:     "8.8.8.8",
	}

	tests := []struct {
		name       string
		expression string
		want       bool
		wantErr    bool
	}{
		{
			name:       "match dst port",
			expression: "DstPort == 443",
			want:       true,
			wantErr:    false,
		},
		{
			name:       "no match dst port",
			expression: "DstPort == 80",
			want:       false,
			wantErr:    false,
		},
		{
			name:       "match src port",
			expression: "SrcPort == 80",
			want:       true,
			wantErr:    false,
		},
		{
			name:       "logical AND true",
			expression: "SrcPort == 80 && DstPort == 443",
			want:       true,
			wantErr:    false,
		},
		{
			name:       "logical AND false",
			expression: "SrcPort == 80 && DstPort == 80",
			want:       false,
			wantErr:    false,
		},
		{
			name:       "logical OR true",
			expression: "SrcPort == 80 || DstPort == 80",
			want:       true,
			wantErr:    false,
		},
		{
			name:       "timestamp comparison",
			expression: "Timestamp > 1000000",
			want:       true,
			wantErr:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			program, err := CompileExpression(tt.expression, types.Type_NC_TCP)
			if err != nil {
				t.Fatalf("Failed to compile expression: %v", err)
			}

			got, err := EvaluateExpression(program, tcp)
			if (err != nil) != tt.wantErr {
				t.Errorf("EvaluateExpression() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("EvaluateExpression() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestEvaluateExpression_WithHelpers(t *testing.T) {
	// Create a test IPv4 record
	ipv4 := &types.IPv4{
		Timestamp: 1234567890,
		SrcIP:     "192.168.1.1",
		DstIP:     "8.8.8.8",
	}

	tests := []struct {
		name       string
		expression string
		want       bool
	}{
		{
			name:       "IsPrivateIP source",
			expression: "IsPrivateIP(SrcIP)",
			want:       true,
		},
		{
			name:       "IsPublicIP destination",
			expression: "IsPublicIP(DstIP)",
			want:       true,
		},
		{
			name:       "InSubnet",
			expression: "InSubnet(SrcIP, \"192.168.0.0/16\")",
			want:       true,
		},
		{
			name:       "private to public",
			expression: "IsPrivateIP(SrcIP) && IsPublicIP(DstIP)",
			want:       true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			program, err := CompileExpression(tt.expression, types.Type_NC_IPv4)
			if err != nil {
				t.Fatalf("Failed to compile expression: %v", err)
			}

			got, err := EvaluateExpression(program, ipv4)
			if err != nil {
				t.Errorf("EvaluateExpression() error = %v", err)
				return
			}
			if got != tt.want {
				t.Errorf("EvaluateExpression() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNestedFieldAccess(t *testing.T) {
	// Create a test TCP record - SrcPort and DstPort are simple int32 fields
	tcp := &types.TCP{
		Timestamp: 1234567890,
		SrcPort:   80,
		DstPort:   443,
		SrcIP:     "192.168.1.1",
		DstIP:     "8.8.8.8",
	}

	tests := []struct {
		name       string
		expression string
		want       bool
	}{
		{
			name:       "simple field access - SrcPort",
			expression: "SrcPort == 80",
			want:       true,
		},
		{
			name:       "simple field access - DstPort",
			expression: "DstPort == 443",
			want:       true,
		},
		{
			name:       "field comparison",
			expression: "SrcPort < DstPort",
			want:       true,
		},
		{
			name:       "field with logical operators",
			expression: "SrcPort == 80 && DstPort == 443",
			want:       true,
		},
		{
			name:       "field non-match",
			expression: "SrcPort == 443",
			want:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			program, err := CompileExpression(tt.expression, types.Type_NC_TCP)
			if err != nil {
				t.Fatalf("Failed to compile expression: %v", err)
			}

			got, err := EvaluateExpression(program, tcp)
			if err != nil {
				t.Errorf("EvaluateExpression() error = %v", err)
				return
			}
			if got != tt.want {
				t.Errorf("EvaluateExpression() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNestedArrayFieldAccess(t *testing.T) {
	// Create a test IPProfile with nested SrcPorts array
	profile := &types.IPProfile{
		Addr: "192.168.1.1",
		SrcPorts: []*types.Port{
			{
				PortNumber: 80,
				Protocol:   "TCP",
			},
			{
				PortNumber: 443,
				Protocol:   "TCP",
			},
		},
		DstPorts: []*types.Port{
			{
				PortNumber: 8080,
				Protocol:   "TCP",
			},
		},
	}

	tests := []struct {
		name       string
		expression string
		want       bool
	}{
		{
			name:       "nested array field access - first element",
			expression: "SrcPorts[0].PortNumber == 80",
			want:       true,
		},
		{
			name:       "nested array field access - second element",
			expression: "SrcPorts[1].PortNumber == 443",
			want:       true,
		},
		{
			name:       "nested array field access - DstPorts",
			expression: "DstPorts[0].PortNumber == 8080",
			want:       true,
		},
		{
			name:       "nested array field with Protocol field",
			expression: "SrcPorts[0].Protocol == \"TCP\"",
			want:       true,
		},
		{
			name:       "nested array field comparison",
			expression: "SrcPorts[0].PortNumber < SrcPorts[1].PortNumber",
			want:       true,
		},
		{
			name:       "nested array field with logical operators",
			expression: "SrcPorts[0].PortNumber == 80 && DstPorts[0].PortNumber == 8080",
			want:       true,
		},
		{
			name:       "nested array field non-match",
			expression: "SrcPorts[0].PortNumber == 443",
			want:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			program, err := CompileExpression(tt.expression, types.Type_NC_IPProfile)
			if err != nil {
				t.Fatalf("Failed to compile expression: %v", err)
			}

			got, err := EvaluateExpression(program, profile)
			if err != nil {
				t.Errorf("EvaluateExpression() error = %v", err)
				return
			}
			if got != tt.want {
				t.Errorf("EvaluateExpression() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestHelperFunctions(t *testing.T) {
	t.Run("InSubnet", func(t *testing.T) {
		tests := []struct {
			ip   string
			cidr string
			want bool
		}{
			{"192.168.1.1", "192.168.0.0/16", true},
			{"10.0.0.1", "192.168.0.0/16", false},
			{"172.16.5.10", "172.16.0.0/12", true},
			{"invalid", "192.168.0.0/16", false},
		}

		for _, tt := range tests {
			got := InSubnet(tt.ip, tt.cidr)
			if got != tt.want {
				t.Errorf("InSubnet(%q, %q) = %v, want %v", tt.ip, tt.cidr, got, tt.want)
			}
		}
	})

	t.Run("IsPrivateIP", func(t *testing.T) {
		tests := []struct {
			ip   string
			want bool
		}{
			{"192.168.1.1", true},
			{"10.0.0.1", true},
			{"172.16.0.1", true},
			{"127.0.0.1", true},
			{"8.8.8.8", false},
			{"1.1.1.1", false},
			{"invalid", false},
		}

		for _, tt := range tests {
			got := IsPrivateIP(tt.ip)
			if got != tt.want {
				t.Errorf("IsPrivateIP(%q) = %v, want %v", tt.ip, got, tt.want)
			}
		}
	})

	t.Run("ParsePort", func(t *testing.T) {
		tests := []struct {
			port string
			want int
		}{
			{"80", 80},
			{"443", 443},
			{"65535", 65535},
			{"0", 0},
			{"invalid", 0},
			{"70000", 0},
			{"-1", 0},
		}

		for _, tt := range tests {
			got := ParsePort(tt.port)
			if got != tt.want {
				t.Errorf("ParsePort(%q) = %v, want %v", tt.port, got, tt.want)
			}
		}
	})

	t.Run("PortInRange", func(t *testing.T) {
		tests := []struct {
			port       int
			start, end int
			want       bool
		}{
			{80, 1, 1024, true},
			{443, 1, 1024, true},
			{8080, 1, 1024, false},
			{1024, 1, 1024, true},
			{1, 1, 1024, true},
		}

		for _, tt := range tests {
			got := PortInRange(tt.port, tt.start, tt.end)
			if got != tt.want {
				t.Errorf("PortInRange(%d, %d, %d) = %v, want %v", tt.port, tt.start, tt.end, got, tt.want)
			}
		}
	})

	t.Run("ContainsAny", func(t *testing.T) {
		tests := []struct {
			str     string
			substrs []string
			want    bool
		}{
			{"hello world", []string{"hello", "goodbye"}, true},
			{"hello world", []string{"goodbye", "farewell"}, false},
			{"test string", []string{"test"}, true},
			{"test string", []string{""}, true},
		}

		for _, tt := range tests {
			got := ContainsAny(tt.str, tt.substrs)
			if got != tt.want {
				t.Errorf("ContainsAny(%q, %v) = %v, want %v", tt.str, tt.substrs, got, tt.want)
			}
		}
	})

	t.Run("MatchesPattern", func(t *testing.T) {
		tests := []struct {
			str     string
			pattern string
			want    bool
		}{
			{"test123", "test[0-9]+", true},
			{"test", "test[0-9]+", false},
			{"hello@world.com", ".*@.*\\.com", true},
			{"invalid", "[", false}, // Invalid regex
		}

		for _, tt := range tests {
			got := MatchesPattern(tt.str, tt.pattern)
			if got != tt.want {
				t.Errorf("MatchesPattern(%q, %q) = %v, want %v", tt.str, tt.pattern, got, tt.want)
			}
		}
	})
}

func TestNilProgram(t *testing.T) {
	tcp := &types.TCP{
		SrcPort: 80,
		DstPort: 443,
	}

	got, err := EvaluateExpression(nil, tcp)
	if err != nil {
		t.Errorf("EvaluateExpression(nil) unexpected error: %v", err)
	}
	if !got {
		t.Errorf("EvaluateExpression(nil) = false, want true (no filter should pass all)")
	}
}
