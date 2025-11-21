package webui

import "testing"

func TestIsPrivateIP(t *testing.T) {
	tests := []struct {
		ip       string
		expected bool
		note     string
	}{
		// ============================================
		// Critical Bug Fix Tests (User Reported)
		// ============================================
		{"191.252.101.74", false, "Bug: Was incorrectly detected as internal (Cloudflare)"},
		{"104.31.69.18", false, "Bug: Was incorrectly detected as internal (Cloudflare)"},
		{"10.10.23.1", true, "Bug test: Should remain internal"},
		{"10.10.23.102", true, "Bug test: Should remain internal"},
		
		// ============================================
		// RFC 1918 Private Networks - Boundaries
		// ============================================
		
		// 10.0.0.0/8 - Class A private network
		{"10.0.0.0", true, "10.0.0.0/8 - Network address"},
		{"10.0.0.1", true, "10.0.0.0/8 - First host"},
		{"10.127.255.255", true, "10.0.0.0/8 - Middle"},
		{"10.255.255.254", true, "10.0.0.0/8 - Last host"},
		{"10.255.255.255", true, "10.0.0.0/8 - Broadcast"},
		{"9.255.255.255", false, "Just before 10/8"},
		{"11.0.0.0", false, "Just after 10/8"},
		
		// 172.16.0.0/12 - Class B private network
		{"172.16.0.0", true, "172.16.0.0/12 - Network address"},
		{"172.16.0.1", true, "172.16.0.0/12 - First host"},
		{"172.23.100.50", true, "172.16.0.0/12 - Middle subnet"},
		{"172.31.255.254", true, "172.16.0.0/12 - Last host"},
		{"172.31.255.255", true, "172.16.0.0/12 - Broadcast"},
		{"172.15.255.255", false, "Just before 172.16/12"},
		{"172.32.0.0", false, "Just after 172.16/12"},
		{"172.0.0.1", false, "172.x but not in private range"},
		{"172.200.0.1", false, "172.x but not in private range"},
		
		// 192.168.0.0/16 - Class C private network
		{"192.168.0.0", true, "192.168.0.0/16 - Network address"},
		{"192.168.0.1", true, "192.168.0.0/16 - First host"},
		{"192.168.1.1", true, "192.168.0.0/16 - Common router"},
		{"192.168.128.128", true, "192.168.0.0/16 - Middle"},
		{"192.168.255.254", true, "192.168.0.0/16 - Last host"},
		{"192.168.255.255", true, "192.168.0.0/16 - Broadcast"},
		{"192.167.255.255", false, "Just before 192.168/16"},
		{"192.169.0.0", false, "Just after 192.168/16"},
		
		// ============================================
		// Special-Use IPv4 Addresses
		// ============================================
		
		// 0.0.0.0/8 - This Network (Critical: was causing the bug!)
		{"0.0.0.0", true, "0.0.0.0/8 - This network"},
		{"0.1.2.3", true, "0.0.0.0/8 - This network"},
		{"0.255.255.255", true, "0.0.0.0/8 - End"},
		
		// 100.64.0.0/10 - Shared Address Space (CGN)
		{"100.64.0.0", true, "CGN - Network address"},
		{"100.64.0.1", true, "CGN - First host"},
		{"100.100.100.100", true, "CGN - Middle"},
		{"100.127.255.254", true, "CGN - Last host"},
		{"100.127.255.255", true, "CGN - Broadcast"},
		{"100.63.255.255", false, "Just before CGN (100.64/10)"},
		{"100.128.0.0", false, "Just after CGN (100.64/10)"},
		{"100.0.0.1", false, "100.x but outside CGN"},
		{"100.250.0.1", false, "100.x but outside CGN"},
		
		// 127.0.0.0/8 - Loopback
		{"127.0.0.0", true, "Loopback - Start"},
		{"127.0.0.1", true, "Loopback - Localhost"},
		{"127.1.1.1", true, "Loopback - Middle"},
		{"127.255.255.255", true, "Loopback - End"},
		{"126.255.255.255", false, "Just before loopback"},
		{"128.0.0.0", false, "Just after loopback"},
		
		// 169.254.0.0/16 - Link-Local (APIPA)
		{"169.254.0.0", true, "Link-Local - Start"},
		{"169.254.1.1", true, "Link-Local - Common APIPA"},
		{"169.254.169.254", true, "Link-Local - AWS metadata service"},
		{"169.254.255.255", true, "Link-Local - End"},
		{"169.253.255.255", false, "Just before Link-Local"},
		{"169.255.0.0", false, "Just after Link-Local"},
		
		// 192.0.0.0/24 - IETF Protocol Assignments
		{"192.0.0.0", true, "IETF Protocol Assignments"},
		{"192.0.0.1", true, "IETF Protocol Assignments"},
		{"192.0.0.255", true, "IETF Protocol Assignments - End"},
		{"192.0.1.0", false, "After IETF Protocol range"},
		
		// 192.0.2.0/24 - TEST-NET-1 (Documentation)
		{"192.0.2.0", true, "TEST-NET-1 - Start"},
		{"192.0.2.1", true, "TEST-NET-1 - Example"},
		{"192.0.2.255", true, "TEST-NET-1 - End"},
		{"192.0.1.255", false, "Before TEST-NET-1"},
		{"192.0.3.0", false, "After TEST-NET-1"},
		
		// 198.18.0.0/15 - Network Interconnect Device Benchmark Testing
		{"198.18.0.0", true, "Benchmark - Start"},
		{"198.18.100.1", true, "Benchmark - 198.18.x.x"},
		{"198.19.100.1", true, "Benchmark - 198.19.x.x"},
		{"198.19.255.255", true, "Benchmark - End"},
		{"198.17.255.255", false, "Before benchmark range"},
		{"198.20.0.0", false, "After benchmark range"},
		
		// 198.51.100.0/24 - TEST-NET-2 (Documentation)
		{"198.51.100.0", true, "TEST-NET-2 - Start"},
		{"198.51.100.1", true, "TEST-NET-2 - Example"},
		{"198.51.100.255", true, "TEST-NET-2 - End"},
		{"198.51.99.255", false, "Before TEST-NET-2"},
		{"198.51.101.0", false, "After TEST-NET-2"},
		
		// 203.0.113.0/24 - TEST-NET-3 (Documentation)
		{"203.0.113.0", true, "TEST-NET-3 - Start"},
		{"203.0.113.1", true, "TEST-NET-3 - Example"},
		{"203.0.113.255", true, "TEST-NET-3 - End"},
		{"203.0.112.255", false, "Before TEST-NET-3"},
		{"203.0.114.0", false, "After TEST-NET-3"},
		
		// 224.0.0.0/4 - Multicast (Class D)
		{"224.0.0.0", true, "Multicast - Start"},
		{"224.0.0.1", true, "Multicast - All Hosts"},
		{"224.0.0.2", true, "Multicast - All Routers"},
		{"230.0.0.1", true, "Multicast - Middle"},
		{"239.255.255.255", true, "Multicast - End"},
		{"223.255.255.255", false, "Before multicast"},
		
		// 240.0.0.0/4 - Reserved for Future Use (Class E)
		{"240.0.0.0", true, "Reserved - Start"},
		{"240.0.0.1", true, "Reserved - First"},
		{"250.0.0.1", true, "Reserved - Middle"},
		{"254.255.255.255", true, "Reserved - Almost end"},
		{"255.255.255.254", true, "Reserved - Before broadcast"},
		
		// 255.255.255.255/32 - Limited Broadcast
		{"255.255.255.255", true, "Limited Broadcast"},
		
		// ============================================
		// Real-World Public IP Examples
		// ============================================
		
		// Major DNS Providers
		{"8.8.8.8", false, "Google Public DNS Primary"},
		{"8.8.4.4", false, "Google Public DNS Secondary"},
		{"1.1.1.1", false, "Cloudflare DNS Primary"},
		{"1.0.0.1", false, "Cloudflare DNS Secondary"},
		{"9.9.9.9", false, "Quad9 DNS"},
		{"208.67.222.222", false, "OpenDNS"},
		{"208.67.220.220", false, "OpenDNS Secondary"},
		
		// Cloud Providers & CDNs
		{"13.107.42.14", false, "Microsoft Azure"},
		{"20.190.0.1", false, "Microsoft Azure"},
		{"52.84.16.1", false, "AWS CloudFront"},
		{"54.239.28.85", false, "AWS"},
		{"34.107.221.82", false, "Google Cloud"},
		{"35.190.247.0", false, "Google Cloud"},
		{"151.101.1.140", false, "Fastly CDN"},
		{"185.199.108.153", false, "GitHub Pages/Fastly"},
		{"104.16.0.1", false, "Cloudflare"},
		{"104.18.0.1", false, "Cloudflare"},
		
		// Major Tech Companies
		{"142.250.185.46", false, "Google"},
		{"172.217.14.206", false, "Google (172.x but public)"},
		{"157.240.241.35", false, "Facebook/Meta"},
		{"31.13.65.1", false, "Facebook/Meta"},
		{"13.225.78.0", false, "Amazon"},
		{"23.195.19.1", false, "Akamai CDN"},
		{"96.16.0.1", false, "Akamai"},
		
		// Various Public Ranges (Boundary Testing)
		{"2.0.0.1", false, "RIPE NCC allocation"},
		{"5.0.0.1", false, "RIPE NCC allocation"},
		{"11.0.0.1", false, "DoD Network (public)"},
		{"15.0.0.1", false, "Hewlett-Packard"},
		{"20.0.0.1", false, "Microsoft"},
		{"50.0.0.1", false, "Various ISPs"},
		{"75.0.0.1", false, "Verizon/Level3"},
		{"99.0.0.1", false, "Various"},
		{"101.0.0.1", false, "APNIC region"},
		{"173.0.0.1", false, "Various (outside 172.16/12)"},
		{"180.0.0.1", false, "APNIC region"},
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
		{"fe80::", true, "IPv6 Link-Local - Start"},
		{"fe80::1", true, "IPv6 Link-Local"},
		{"fe80::dead:beef", true, "IPv6 Link-Local"},
		{"fe80:1234:5678:9abc:def0:1234:5678:9abc", true, "IPv6 Link-Local (full)"},
		{"febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff", true, "IPv6 Link-Local - End"},
		{"fe7f:ffff:ffff:ffff:ffff:ffff:ffff:ffff", false, "Before IPv6 Link-Local"},
		{"fec0::1", false, "After IPv6 Link-Local"},
		
		// IPv6 Unique Local (fc00::/7)
		{"fc00::", true, "IPv6 Unique Local - Start"},
		{"fc00::1", true, "IPv6 Unique Local"},
		{"fd00::", true, "IPv6 Unique Local"},
		{"fd00::1234:5678", true, "IPv6 Unique Local"},
		{"fd12:3456:789a:bcde::", true, "IPv6 Unique Local"},
		{"fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", true, "IPv6 Unique Local - End"},
		{"fbff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", false, "Before IPv6 Unique Local"},
		{"fe00::1", false, "After IPv6 Unique Local"},
		
		// IPv6 Multicast (ff00::/8)
		{"ff00::", true, "IPv6 Multicast - Start"},
		{"ff01::1", true, "IPv6 Multicast Interface-Local"},
		{"ff02::1", true, "IPv6 Multicast Link-Local (All Nodes)"},
		{"ff02::2", true, "IPv6 Multicast Link-Local (All Routers)"},
		{"ff05::1", true, "IPv6 Multicast Site-Local"},
		{"ff0e::1", true, "IPv6 Multicast Global"},
		{"ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", true, "IPv6 Multicast - End"},
		{"feff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", false, "Before IPv6 Multicast"},
		
		// IPv6 Documentation (2001:db8::/32)
		{"2001:db8::", true, "IPv6 Documentation - Start"},
		{"2001:db8::1", true, "IPv6 Documentation"},
		{"2001:db8:1234::", true, "IPv6 Documentation"},
		{"2001:db8:1234:5678::", true, "IPv6 Documentation"},
		{"2001:db8:ffff:ffff:ffff:ffff:ffff:ffff", true, "IPv6 Documentation - End"},
		{"2001:db7:ffff:ffff:ffff:ffff:ffff:ffff", false, "Before IPv6 Documentation"},
		{"2001:db9::", false, "After IPv6 Documentation"},
		
		// IPv6 Public Addresses
		{"2001:4860:4860::8888", false, "Google Public DNS IPv6"},
		{"2001:4860:4860::8844", false, "Google Public DNS IPv6 Secondary"},
		{"2606:4700:4700::1111", false, "Cloudflare DNS IPv6"},
		{"2606:4700:4700::1001", false, "Cloudflare DNS IPv6 Secondary"},
		{"2620:fe::fe", false, "Quad9 DNS IPv6"},
		{"2a00:1450:4001::1", false, "Google Europe"},
		{"2607:f8b0:4004::", false, "Google USA"},
		{"2001:500::", false, "Root DNS Server"},
		{"2001:500:200::b", false, "Root DNS Server"},
		
		// ============================================
		// Edge Cases & Invalid Inputs
		// ============================================
		
		// Empty and null
		{"", false, "Empty string"},
		
		// Invalid IPv4 formats
		{"invalid", false, "Invalid text"},
		{"256.1.1.1", false, "Octet > 255"},
		{"1.1.1", false, "Too few octets"},
		{"1.1.1.1.1", false, "Too many octets"},
		{"999.999.999.999", false, "All octets > 255"},
		{"192.168.1", false, "Incomplete"},
		{"-1.0.0.0", false, "Negative octet"},
		{"1.2.3.four", false, "Non-numeric"},
		{"1.2.3.4.5.6", false, "Way too many octets"},
		{"a.b.c.d", false, "All non-numeric"},
		
		// IPv6 malformed
		{"gggg::1", false, "Invalid hex in IPv6"},
		{"::1::2", false, "Multiple :: in IPv6"},
		{"2001:db8:::1", false, "Triple colon"},
		{"2001:db8:xyz::1", false, "Non-hex in IPv6"},
		
		// Whitespace variations
		{" 192.168.1.1", false, "Leading space"},
		{"192.168.1.1 ", false, "Trailing space"},
		{" 192.168.1.1 ", false, "Both spaces"},
		
		// Special characters
		{"192.168.1.1/24", false, "CIDR notation (not an IP)"},
		{"192.168.1.1:80", false, "Port included"},
		{"http://192.168.1.1", false, "URL with IP"},
	}
	
	// Track failures for summary
	failures := 0
	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			got := isPrivateIP(tt.ip)
			if got != tt.expected {
				t.Errorf("isPrivateIP(%q) = %v, want %v [%s]", tt.ip, got, tt.expected, tt.note)
				failures++
			}
		})
	}
	
	// Summary
	if failures == 0 {
		t.Logf("✅ All %d test cases passed!", len(tests))
	}
}

