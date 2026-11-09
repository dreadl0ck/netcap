package networkdetect

import (
	"fmt"
	"github.com/dreadl0ck/netcap/types"
	"testing"
)

func TestVariablePOSTBeaconIsOneIncident(t *testing.T) {
	for _, ranges := range []bool{false, true} {
		e := NewApplication(DefaultConfig())
		var alerts []*types.Alert
		for i := 0; i < 200; i++ {
			o := httpObservation(i * 30)
			o.Method = "POST"
			o.Path = fmt.Sprintf("/random-%d/encoded", i)
			o.Status = 200
			o.RangeTransfer = ranges
			alerts = append(alerts, e.Observe(o)...)
		}
		alerts = append(alerts, e.Flush()...)
		if ranges && len(alerts) != 0 {
			t.Fatal("range transfer classified as beacon")
		}
		if !ranges && (len(alerts) != 1 || alerts[0].Name != "c2.beacon" || alerts[0].Count != 193) {
			t.Fatalf("beacon incident split: %+v", alerts)
		}
	}
}

func TestDNScatThroughForwarder(t *testing.T) {
	c := DefaultConfig()
	e, _ := New(c)
	var alerts []*types.Alert
	for i := 0; i < 20; i++ {
		ev := baseEvent("dns", i)
		ev.SrcIP = "10.0.0.53"
		ev.DstIP = "198.51.100.53"
		ev.DstPort = 53
		ev.QType = 1
		ev.Name = fmt.Sprintf("dnscat.%04x01abcd0123456789abcdef0123456789abcdef.example.net", i)
		got, err := e.Observe(ev)
		if err != nil {
			t.Fatal(err)
		}
		alerts = append(alerts, got...)
	}
	alerts = append(alerts, e.Flush()...)
	found := false
	for _, a := range alerts {
		if a.Name == "dns.tunnel" {
			found = true
			if a.DstPort != "53" || a.Domain != "example.net" {
				t.Fatal(a)
			}
		}
	}
	if !found {
		t.Fatal("forwarder tunnel missed")
	}
}

func TestTCPConflictingOverlapDistinguishesRetransmission(t *testing.T) {
	for _, conflict := range []bool{false, true} {
		e, _ := New(DefaultConfig())
		ev := baseEvent("data", 1)
		ev.Seq = 100
		ev.Payload = []byte("HTTP/1.1 302 Found\r\n\r\n")
		if _, err := e.Observe(ev); err != nil {
			t.Fatal(err)
		}
		ev.At++
		if conflict {
			ev.Payload = []byte("HTTP/1.1 200 OK   \r\n\r\n")
		}
		got, err := e.Observe(ev)
		if err != nil {
			t.Fatal(err)
		}
		got = append(got, e.Flush()...)
		if conflict && (len(got) != 1 || got[0].Name != "tcp.overlap-conflict" || e.Stats().ConflictingOverlaps != 1) {
			t.Fatal(got, e.Stats())
		}
		if !conflict && len(got) != 0 {
			t.Fatal("ordinary retransmission alerted", got)
		}
	}
}

func TestSensitiveADRequestsAreQualified(t *testing.T) {
	e := NewApplication(DefaultConfig())
	var alerts []*types.Alert
	for i := 0; i < 40; i++ {
		o := httpObservation(i)
		o.Kind = "rpc"
		o.Method = "12345678-1234-abcd-ef00-01234567cffb"
		o.Status = 26
		alerts = append(alerts, e.Observe(o)...)
	}
	o := httpObservation(41)
	o.Kind = "rpc"
	o.Method = "e3514235-4b06-11d1-ab04-00c04fc2dcd2"
	o.Status = 3
	alerts = append(alerts, e.Observe(o)...)
	alerts = append(alerts, e.Flush()...)
	seen := map[string]bool{}
	for _, a := range alerts {
		seen[a.Name] = true
	}
	if !seen["ad.netlogon-authentication-burst"] || !seen["ad.directory-replication"] {
		t.Fatal(seen)
	}
}
