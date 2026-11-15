package networkdetect

import (
	"strings"
	"testing"
)

func TestBinaryNULLTunnelBeforeHostnameValidation(t *testing.T) {
	for _, tunneled := range []bool{false, true} {
		cfg := DefaultConfig()
		cfg.DNSNames = 4
		e, err := New(cfg)
		if err != nil {
			t.Fatal(err)
		}
		for i := 0; i < 20; i++ {
			ev := baseEvent("dns", i+1)
			ev.QType = 10
			ev.DstPort = 53
			label := make([]byte, 48)
			for j := range label {
				label[j] = byte(0x80 + (j+i)%64)
			}
			label[0] = 0
			ev.Name = string(label) + ".Tunnel.Example.NET"
			if !tunneled {
				ev.Name = "ordinary.example.net"
			}
			if _, err := e.Observe(ev); err != nil {
				t.Fatal(err)
			}
		}
		found := false
		for _, a := range e.Flush() {
			if a.Name == "dns.tunnel" {
				found = true
				if a.Domain != "example.net" || strings.Contains(a.MatchedRecord, "\ufffd") {
					t.Fatal(a)
				}
			}
		}
		if found != tunneled {
			t.Fatalf("tunnel=%t detected=%t", tunneled, found)
		}
	}
}
