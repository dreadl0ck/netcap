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
			note string
		}{
			// ============================================
			// RFC 1918 Private Networks - Comprehensive
			// ============================================
			
			// 10.0.0.0/8 - Boundaries and examples
			{"10.0.0.0", true, "10.0.0.0/8 - Start of range"},
			{"10.0.0.1", true, "10.0.0.0/8 - First usable"},
			{"10.10.23.1", true, "10.0.0.0/8 - User reported IP"},
			{"10.10.23.102", true, "10.0.0.0/8 - User reported IP"},
			{"10.128.0.0", true, "10.0.0.0/8 - Middle of range"},
			{"10.255.255.254", true, "10.0.0.0/8 - Last usable"},
			{"10.255.255.255", true, "10.0.0.0/8 - End of range"},
			{"9.255.255.255", false, "Just before 10.0.0.0/8"},
			{"11.0.0.0", false, "Just after 10.0.0.0/8"},
			
			// 172.16.0.0/12 - Boundaries and examples
			{"172.16.0.0", true, "172.16.0.0/12 - Start of range"},
			{"172.16.0.1", true, "172.16.0.0/12 - First usable"},
			{"172.20.0.1", true, "172.16.0.0/12 - Middle subnet"},
			{"172.31.255.254", true, "172.16.0.0/12 - Last usable"},
			{"172.31.255.255", true, "172.16.0.0/12 - End of range"},
			{"172.15.255.255", false, "Just before 172.16.0.0/12"},
			{"172.32.0.0", false, "Just after 172.16.0.0/12"},
			{"172.0.0.1", false, "172.x outside private range"},
			{"172.100.0.1", false, "172.x outside private range"},
			
			// 192.168.0.0/16 - Boundaries and examples
			{"192.168.0.0", true, "192.168.0.0/16 - Start of range"},
			{"192.168.0.1", true, "192.168.0.0/16 - First usable"},
			{"192.168.1.1", true, "192.168.0.0/16 - Common router IP"},
			{"192.168.100.50", true, "192.168.0.0/16 - Middle subnet"},
			{"192.168.255.254", true, "192.168.0.0/16 - Last usable"},
			{"192.168.255.255", true, "192.168.0.0/16 - End of range"},
			{"192.167.255.255", false, "Just before 192.168.0.0/16"},
			{"192.169.0.0", false, "Just after 192.168.0.0/16"},
			
			// ============================================
			// Special-Use IPv4 Addresses - Comprehensive
			// ============================================
			
			// 0.0.0.0/8 - "This" Network
			{"0.0.0.0", true, "0.0.0.0/8 - This Network"},
			{"0.0.0.1", true, "0.0.0.0/8 - This Network"},
			{"0.255.255.255", true, "0.0.0.0/8 - End of range"},
			
			// 100.64.0.0/10 - Shared Address Space (CGN/Carrier-Grade NAT)
			{"100.64.0.0", true, "100.64.0.0/10 - CGN Start"},
			{"100.64.0.1", true, "100.64.0.0/10 - CGN First usable"},
			{"100.80.0.1", true, "100.64.0.0/10 - CGN Middle"},
			{"100.127.255.254", true, "100.64.0.0/10 - CGN Last usable"},
			{"100.127.255.255", true, "100.64.0.0/10 - CGN End"},
			{"100.63.255.255", false, "Just before CGN range"},
			{"100.128.0.0", false, "Just after CGN range"},
			{"100.0.0.1", false, "100.x outside CGN range"},
			{"100.200.0.1", false, "100.x outside CGN range"},
			
			// 127.0.0.0/8 - Loopback
			{"127.0.0.0", true, "127.0.0.0/8 - Loopback start"},
			{"127.0.0.1", true, "127.0.0.0/8 - Localhost"},
			{"127.1.1.1", true, "127.0.0.0/8 - Loopback middle"},
			{"127.255.255.255", true, "127.0.0.0/8 - Loopback end"},
			
			// 169.254.0.0/16 - Link-Local (APIPA)
			{"169.254.0.0", true, "169.254.0.0/16 - Link-Local start"},
			{"169.254.0.1", true, "169.254.0.0/16 - Link-Local first"},
			{"169.254.100.1", true, "169.254.0.0/16 - Link-Local middle"},
			{"169.254.255.255", true, "169.254.0.0/16 - Link-Local end"},
			{"169.253.255.255", false, "Just before Link-Local"},
			{"169.255.0.0", false, "Just after Link-Local"},
			
			// 192.0.0.0/24 - IETF Protocol Assignments
			{"192.0.0.0", true, "192.0.0.0/24 - IETF Protocol"},
			{"192.0.0.1", true, "192.0.0.0/24 - IETF Protocol"},
			{"192.0.0.255", true, "192.0.0.0/24 - IETF Protocol end"},
			{"192.0.1.0", false, "Just after 192.0.0.0/24"},
			
			// 192.0.2.0/24 - TEST-NET-1 (Documentation)
			{"192.0.2.0", true, "192.0.2.0/24 - TEST-NET-1"},
			{"192.0.2.1", true, "192.0.2.0/24 - TEST-NET-1"},
			{"192.0.2.255", true, "192.0.2.0/24 - TEST-NET-1 end"},
			{"192.0.1.255", false, "Just before TEST-NET-1"},
			{"192.0.3.0", false, "Just after TEST-NET-1"},
			
			// 198.18.0.0/15 - Benchmarking
			{"198.18.0.0", true, "198.18.0.0/15 - Benchmarking start"},
			{"198.18.0.1", true, "198.18.0.0/15 - Benchmarking"},
			{"198.18.255.255", true, "198.18.0.0/15 - Benchmarking"},
			{"198.19.0.0", true, "198.18.0.0/15 - Benchmarking"},
			{"198.19.255.255", true, "198.18.0.0/15 - Benchmarking end"},
			{"198.17.255.255", false, "Just before Benchmarking range"},
			{"198.20.0.0", false, "Just after Benchmarking range"},
			
			// 198.51.100.0/24 - TEST-NET-2 (Documentation)
			{"198.51.100.0", true, "198.51.100.0/24 - TEST-NET-2"},
			{"198.51.100.1", true, "198.51.100.0/24 - TEST-NET-2"},
			{"198.51.100.255", true, "198.51.100.0/24 - TEST-NET-2 end"},
			{"198.51.99.255", false, "Just before TEST-NET-2"},
			{"198.51.101.0", false, "Just after TEST-NET-2"},
			
			// 203.0.113.0/24 - TEST-NET-3 (Documentation)
			{"203.0.113.0", true, "203.0.113.0/24 - TEST-NET-3"},
			{"203.0.113.1", true, "203.0.113.0/24 - TEST-NET-3"},
			{"203.0.113.255", true, "203.0.113.0/24 - TEST-NET-3 end"},
			{"203.0.112.255", false, "Just before TEST-NET-3"},
			{"203.0.114.0", false, "Just after TEST-NET-3"},
			
			// 224.0.0.0/4 - Multicast
			{"224.0.0.0", true, "224.0.0.0/4 - Multicast start"},
			{"224.0.0.1", true, "224.0.0.0/4 - All Hosts multicast"},
			{"239.0.0.1", true, "224.0.0.0/4 - Multicast middle"},
			{"239.255.255.255", true, "224.0.0.0/4 - Multicast end"},
			{"223.255.255.255", false, "Just before Multicast range"},
			
			// 240.0.0.0/4 - Reserved (Class E)
			{"240.0.0.0", true, "240.0.0.0/4 - Reserved start"},
			{"240.0.0.1", true, "240.0.0.0/4 - Reserved"},
			{"250.0.0.1", true, "240.0.0.0/4 - Reserved middle"},
			{"254.255.255.255", true, "240.0.0.0/4 - Reserved"},
			
			// 255.255.255.255/32 - Limited Broadcast
			{"255.255.255.255", true, "255.255.255.255/32 - Broadcast"},
			
			// ============================================
			// Real-World Public IP Addresses
			// ============================================
			
			// DNS Servers
			{"8.8.8.8", false, "Google Public DNS"},
			{"8.8.4.4", false, "Google Public DNS Secondary"},
			{"1.1.1.1", false, "Cloudflare DNS"},
			{"1.0.0.1", false, "Cloudflare DNS Secondary"},
			{"9.9.9.9", false, "Quad9 DNS"},
			{"208.67.222.222", false, "OpenDNS"},
			
			// CDN & Cloud Providers
			{"104.31.69.18", false, "Cloudflare CDN"},
			{"191.252.101.74", false, "Cloudflare CDN"},
			{"13.107.42.14", false, "Microsoft Azure"},
			{"52.84.16.1", false, "AWS CloudFront"},
			{"34.107.221.82", false, "Google Cloud"},
			{"151.101.1.140", false, "Fastly CDN"},
			{"185.199.108.153", false, "GitHub Pages"},
			
			// Major Websites & Services
			{"142.250.185.46", false, "Google"},
			{"157.240.241.35", false, "Facebook/Meta"},
			{"31.13.65.1", false, "Facebook/Meta"},
			{"13.225.78.0", false, "Amazon"},
			{"23.195.19.1", false, "Akamai CDN"},
			
			// Various Public Ranges
			{"2.0.0.1", false, "RIPE NCC"},
			{"5.0.0.1", false, "RIPE NCC"},
			{"11.0.0.1", false, "DoD Network"},
			{"15.0.0.1", false, "Hewlett-Packard"},
			{"20.0.0.1", false, "Microsoft"},
			{"50.0.0.1", false, "Various ISPs"},
			{"75.0.0.1", false, "Verizon/Level3"},
			{"99.0.0.1", false, "Various"},
			{"173.0.0.1", false, "Outside 172.16.0.0/12"},
			{"191.0.0.1", false, "LACNIC region"},
			{"200.0.0.1", false, "LACNIC region"},
			{"210.0.0.1", false, "APNIC region"},
			
			// ============================================
			// IPv6 Addresses - Comprehensive
			// ============================================
			
			// IPv6 Loopback
			{"::1", true, "IPv6 Loopback"},
			{"0:0:0:0:0:0:0:1", true, "IPv6 Loopback (expanded)"},
			
			// IPv6 Unspecified
			{"::", true, "IPv6 Unspecified"},
			{"0:0:0:0:0:0:0:0", true, "IPv6 Unspecified (expanded)"},
			
			// IPv6 Link-Local (fe80::/10)
			{"fe80::", true, "IPv6 Link-Local"},
			{"fe80::1", true, "IPv6 Link-Local"},
			{"fe80::dead:beef", true, "IPv6 Link-Local"},
			{"febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff", true, "IPv6 Link-Local end"},
			{"fec0::1", false, "Outside IPv6 Link-Local"},
			
			// IPv6 Unique Local (fc00::/7)
			{"fc00::", true, "IPv6 Unique Local"},
			{"fc00::1", true, "IPv6 Unique Local"},
			{"fd00::", true, "IPv6 Unique Local"},
			{"fd00::1234:5678", true, "IPv6 Unique Local"},
			{"fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", true, "IPv6 Unique Local end"},
			{"fe00::1", false, "Outside IPv6 Unique Local"},
			{"fb00::1", false, "Outside IPv6 Unique Local"},
			
			// IPv6 Multicast (ff00::/8)
			{"ff00::", true, "IPv6 Multicast"},
			{"ff01::1", true, "IPv6 Multicast Interface-Local"},
			{"ff02::1", true, "IPv6 Multicast Link-Local"},
			{"ff05::1", true, "IPv6 Multicast Site-Local"},
			{"ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", true, "IPv6 Multicast end"},
			
			// IPv6 Documentation (2001:db8::/32)
			{"2001:db8::", true, "IPv6 Documentation"},
			{"2001:db8::1", true, "IPv6 Documentation"},
			{"2001:db8:1234:5678::", true, "IPv6 Documentation"},
			{"2001:db8:ffff:ffff:ffff:ffff:ffff:ffff", true, "IPv6 Documentation end"},
			{"2001:db7:ffff:ffff:ffff:ffff:ffff:ffff", false, "Just before IPv6 Documentation"},
			{"2001:db9::", false, "Just after IPv6 Documentation"},
			
			// IPv6 Public Addresses
			{"2001:4860:4860::8888", false, "Google Public DNS IPv6"},
			{"2606:4700:4700::1111", false, "Cloudflare DNS IPv6"},
			{"2a00:1450:4001::1", false, "Google Europe"},
			{"2607:f8b0:4004::", false, "Google USA"},
			{"2001:500::", false, "Root DNS Server"},
			
			// ============================================
			// Edge Cases & Invalid Inputs
			// ============================================
			
			// Invalid formats
			{"", false, "Empty string"},
			{"invalid", false, "Invalid IP string"},
			{"256.1.1.1", false, "Octet > 255"},
			{"1.1.1", false, "Too few octets"},
			{"1.1.1.1.1", false, "Too many octets"},
			{"999.999.999.999", false, "All octets out of range"},
			{"192.168.1", false, "Incomplete IPv4"},
			{"192.168.1.1.1", false, "Too many parts"},
			{"-1.0.0.0", false, "Negative octet"},
			{"1.2.3.four", false, "Non-numeric octet"},
			{"192.168.001.001", false, "Leading zeros (ambiguous)"},
			
			// IPv6 malformed
			{"gggg::1", false, "Invalid IPv6 hex"},
			{"::1::2", false, "Double :: in IPv6"},
			{"2001:db8:::1", false, "Triple colon in IPv6"},
			
			// Localhost variations (should all be private)
			{"127.1.2.3", true, "Loopback variant"},
			{"127.254.254.254", true, "Loopback variant"},
		}

		for _, tt := range tests {
			got := IsPrivateIP(tt.ip)
			if got != tt.want {
				t.Errorf("IsPrivateIP(%q) = %v, want %v [%s]", tt.ip, got, tt.want, tt.note)
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
