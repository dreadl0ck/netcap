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

func TestOverlapEvidenceSurvivesCloseButNotNewSession(t *testing.T) {
	for _, mode := range []string{"conflict", "retransmission", "new-syn", "expired"} {
		t.Run(mode, func(t *testing.T) {
			c := DefaultConfig()
			e, _ := New(c)
			ev := baseEvent("data", 1)
			ev.Seq, ev.Payload = 100, []byte("HTTP/1.1 302 Found\r\n\r\n")
			observe := func() []*types.Alert {
				got, err := e.Observe(ev)
				if err != nil {
					t.Fatal(err)
				}
				return got
			}
			observe()
			ev.At++
			ev.Kind, ev.Payload = "end", nil
			observe()
			if mode == "new-syn" {
				ev.Kind, ev.Seq = "syn", 99
				observe()
			}
			if mode == "expired" {
				ev.At += c.WindowNS + 1
			}
			ev.Kind, ev.Seq, ev.Payload = "data", 100, []byte("HTTP/1.1 200 OK   \r\n\r\n")
			if mode == "retransmission" {
				ev.Payload = []byte("HTTP/1.1 302 Found\r\n\r\n")
			}
			got := append(observe(), e.Flush()...)
			if mode == "conflict" {
				if len(got) != 1 || got[0].Name != "tcp.overlap-conflict" {
					t.Fatal("post-close conflict missed", got)
				}
			} else if len(got) != 0 {
				t.Fatal("session boundary/retransmission produced conflict", got)
			}
		})
	}
}

func TestANSIServiceControlAndAuthenticate2AreObserved(t *testing.T) {
	for _, op := range []int{12, 19, 24, 31, 16} {
		e := NewApplication(DefaultConfig())
		o := httpObservation(1)
		o.Kind, o.Method, o.Status = "rpc", "367abb81-9844-35f1-ad32-98f038001003", op
		got := append(e.Observe(o), e.Flush()...)
		if op == 16 {
			if len(got) != 0 {
				t.Fatal("opening a service triggered create/start policy", got)
			}
		} else if len(got) != 1 || got[0].Name != "smb.remote-service-control" {
			t.Fatal("service create/start omitted", op, got)
		}
	}
	for _, op := range []int{4, 15, 26} {
		e := NewApplication(DefaultConfig())
		var got []*types.Alert
		for i := 0; i < 40; i++ {
			o := httpObservation(i)
			o.Kind, o.Method, o.Status = "rpc", "12345678-1234-abcd-ef00-01234567cffb", op
			got = append(got, e.Observe(o)...)
		}
		got = append(got, e.Flush()...)
		if op == 4 {
			if len(got) != 0 {
				t.Fatal("challenge-only calls classified as authentication burst", got)
			}
		} else if len(got) != 1 || got[0].Name != "ad.netlogon-authentication-burst" {
			t.Fatal("authentication variant omitted", op, got)
		}
	}
}

func TestPOSTBeaconWithSkippedPolls(t *testing.T) {
	for _, mode := range []string{"cadence", "irregular", "range", "GET"} {
		t.Run(mode, func(t *testing.T) {
			e := NewApplication(DefaultConfig())
			gaps := []int{30, 60, 30, 90, 30, 60, 30, 120, 30}
			if mode == "irregular" {
				gaps = []int{30, 47, 83, 61, 41, 74, 103, 45, 75}
			}
			seconds := 0
			var alerts []*types.Alert
			for i := 0; i <= len(gaps); i++ {
				o := httpObservation(seconds)
				o.Method, o.Path, o.RangeTransfer = "POST", fmt.Sprintf("/encoded-%d", i), mode == "range"
				if mode == "GET" {
					o.Method = "GET"
					o.Path = "/fixed"
				}
				alerts = append(alerts, e.Observe(o)...)
				if i < len(gaps) {
					seconds += gaps[i]
				}
			}
			alerts = append(alerts, e.Flush()...)
			if mode == "cadence" {
				if len(alerts) != 1 || alerts[0].Name != "c2.beacon" {
					t.Fatal("skipped polls missed", alerts)
				}
			} else if len(alerts) != 0 {
				t.Fatal("negative control classified as fitted POST cadence", mode, alerts)
			}
		})
	}
}
