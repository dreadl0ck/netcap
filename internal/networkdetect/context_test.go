package networkdetect

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/types"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

type ftpTrace struct {
	events               []Event
	control              Event
	at                   int64
	clientSeq, serverSeq uint32
}

func newFTPTrace(ports ...uint16) *ftpTrace {
	f := &ftpTrace{control: baseEvent("syn", 0), clientSeq: 100, serverSeq: 500}
	f.control.At, f.control.Seq, f.control.DstPort = 0, 99, 21
	if len(ports) != 0 {
		f.control.DstPort = ports[0]
	}
	f.events = append(f.events, f.control)
	f.line(false, "220 FTP ready\r\n")
	return f
}

func (f *ftpTrace) line(client bool, text string) {
	ev := f.control
	f.at += 10e6
	ev.At, ev.Kind, ev.Payload = f.at, "data", []byte(text)
	if client {
		ev.Seq = f.clientSeq
		f.clientSeq += uint32(len(text))
	} else {
		ev.SrcIP, ev.DstIP, ev.SrcPort, ev.DstPort = ev.DstIP, ev.SrcIP, ev.DstPort, ev.SrcPort
		ev.Seq = f.serverSeq
		f.serverSeq += uint32(len(text))
	}
	f.events = append(f.events, ev)
}

func (f *ftpTrace) data(port uint16) Event {
	ev := f.control
	f.at += 10e6
	ev.At, ev.SrcIP, ev.DstIP, ev.SrcPort, ev.DstPort = f.at, ev.DstIP, ev.SrcIP, 20, port
	ev.Seq = uint32(port)
	f.events = append(f.events, ev)
	return ev
}

func packetReplay(t *testing.T, c Config, events []Event) ([]*types.Alert, Stats) {
	t.Helper()
	e, err := New(c)
	if err != nil {
		t.Fatal(err)
	}
	var alerts []*types.Alert
	for _, ev := range events {
		data := packetForEvent(t, ev)
		p := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.Default)
		p.Metadata().CaptureInfo.Timestamp = time.Unix(0, ev.At)
		for _, decoded := range PacketEvents(p, ev.Scope) {
			rows, err := e.Observe(decoded)
			if err != nil {
				t.Fatal(err)
			}
			alerts = append(alerts, rows...)
		}
	}
	return append(alerts, e.Flush()...), e.Stats()
}

func TestActiveFTPNegotiationExcludesOnlyNegotiatedData(t *testing.T) {
	for _, mode := range []string{"PORT", "EPRT", "nonstandard", "rejected", "no-reply", "no-transfer", "third-party", "gap", "overlong", "expired", "passive", "other-scope", "other-peer", "transfer-rejected", "control-ended", "reused-tuple"} {
		t.Run(mode, func(t *testing.T) {
			f := newFTPTrace()
			if mode == "nonstandard" {
				f = newFTPTrace(2121)
			}
			for i := 0; i < 57; i++ {
				port := uint16(40000 + i)
				command := fmt.Sprintf("PORT 192,0,2,10,%d,%d\r\n", port/256, port%256)
				if mode == "EPRT" {
					command = fmt.Sprintf("EPRT |1|192.0.2.10|%d|\r\n", port)
				}
				if mode == "third-party" {
					command = strings.Replace(command, "192,0,2,10", "192,0,2,11", 1)
				}
				if mode == "gap" {
					f.clientSeq++
				}
				if mode == "overlong" {
					f.line(true, strings.Repeat("X", 513)+"\r\n")
				}
				// Split negotiation at a TCP segment boundary; replay a retransmission.
				f.line(true, command[:5])
				f.events = append(f.events, f.events[len(f.events)-1])
				f.line(true, command[5:])
				if mode == "rejected" {
					f.line(false, "500 PORT refused\r\n")
				} else if mode != "no-reply" {
					f.line(false, "200-accepted\r\n200 PORT command successful\r\n")
				}
				if mode == "passive" {
					f.line(true, "PASV\r\n")
					f.line(false, "227 Entering passive mode\r\n")
				}
				if mode != "no-transfer" {
					f.line(true, "RETR "+strings.Repeat("f", 80)+"\r\n")
				}
				if mode == "transfer-rejected" {
					f.line(false, "550 File unavailable\r\n")
				}
				if mode == "control-ended" {
					ev := f.control
					ev.Kind, ev.At = "end", f.at
					f.events = append(f.events, ev)
				}
				if mode == "expired" {
					f.at += ftpDataLifetimeNS
				}
				data := f.data(port)
				if mode == "other-scope" {
					f.events[len(f.events)-1].Scope.Interface = "other"
				}
				if mode == "other-peer" {
					f.events[len(f.events)-1].SrcIP = "198.51.100.11"
				}
				if mode == "reused-tuple" {
					data.Seq++
					f.events = append(f.events, data)
				} else {
					// Retrying the same negotiated SYN must not poison scan counters.
					f.events = append(f.events, f.events[len(f.events)-1])
				}
				f.line(false, "226 Transfer complete\r\n")
			}
			c := DefaultConfig()
			c.BeaconSamples, c.WindowNS = 0, 86400e9
			alerts, stats := packetReplay(t, c, f.events)
			found := false
			for _, a := range alerts {
				found = found || a.Name == "network.scan"
			}
			valid := mode == "PORT" || mode == "EPRT" || mode == "nonstandard"
			if found == valid || valid && stats.FTPDataExclusions != 114 {
				t.Fatalf("scan=%v validNegotiation=%v stats=%+v", found, valid, stats)
			}
		})
	}
}

func TestPort20AloneStillScansAndFTPDoesNotBypassIntel(t *testing.T) {
	var events []Event
	for i := 0; i < 15; i++ {
		ev := baseEvent("syn", i)
		ev.SrcPort, ev.DstPort = 20, uint16(40000+i)
		events = append(events, ev)
	}
	alerts, _ := packetReplay(t, DefaultConfig(), events)
	if len(alerts) != 1 || alerts[0].Name != "network.scan" || alerts[0].Count != 6 {
		t.Fatal(alerts)
	}
	f := newFTPTrace()
	f.line(true, "PORT 192,0,2,10,156,64\r\n")
	f.line(false, "200 OK\r\n")
	f.line(true, "LIST\r\n")
	f.data(40000)
	c := DefaultConfig()
	c.Indicators = []Indicator{{Value: "192.0.2.10", Kind: "ip", Category: "c2", Source: "synthetic", Version: "1", ValidFrom: 0, ValidUntil: 1e9}}
	alerts, stats := packetReplay(t, c, f.events)
	if stats.FTPDataExclusions != 1 || len(alerts) != 1 || alerts[0].Name != "intel.c2" {
		t.Fatal(stats, alerts)
	}
}

func TestPassiveFTPNegotiationAndMalformedControls(t *testing.T) {
	for _, mode := range []string{"PASV", "EPSV", "third-party", "unsolicited", "wrong-code", "malformed", "expired", "reused"} {
		t.Run(mode, func(t *testing.T) {
			f := newFTPTrace()
			for i := 0; i < 15; i++ {
				port := uint16(40000 + i)
				op := "PASV"
				reply := fmt.Sprintf("227 Entering Passive Mode (198,51,100,10,%d,%d)\r\n", port/256, port%256)
				switch mode {
				case "EPSV":
					op, reply = "EPSV", fmt.Sprintf("229 Extended Passive Mode (|||%d|)\r\n", port)
				case "third-party":
					reply = strings.Replace(reply, "198,51,100,10", "198,51,100,11", 1)
				case "wrong-code":
					reply = strings.Replace(reply, "227", "500", 1)
				case "malformed":
					reply = "227 Entering Passive Mode (198,51,100,10,256,0)\r\n"
				}
				if mode != "unsolicited" {
					f.line(true, op+"\r\n")
				}
				f.line(false, reply)
				if mode == "expired" {
					f.at += ftpDataLifetimeNS
				}
				ev := f.control
				f.at += 10e6
				ev.At, ev.SrcPort, ev.DstPort, ev.Seq = f.at, 50000, port, uint32(i)
				f.events = append(f.events, ev)
				if mode == "reused" {
					ev.Seq++
					f.events = append(f.events, ev)
				}
			}
			c := DefaultConfig()
			c.WindowNS, c.BeaconSamples = 86400e9, 0
			rows, stats := packetReplay(t, c, f.events)
			valid := mode == "PASV" || mode == "EPSV"
			scan := false
			for _, row := range rows {
				scan = scan || row.Name == "network.scan"
			}
			if scan == valid || valid && stats.FTPDataExclusions != 15 {
				t.Fatal(mode, rows, stats)
			}
		})
	}
	for _, tuple := range []string{"(|||0|)", "(|||65536|)", "(||1|40000|)", "(|||40000)", "(|||40000||)"} {
		if _, ok := ftpPassiveTarget("EPSV", 229, "229 "+tuple, "2001:db8::1"); ok {
			t.Fatal("accepted malformed EPSV", tuple)
		}
	}
}

func TestFTPStateBoundsAndIPv6Targets(t *testing.T) {
	if p, ok := ftpActiveTarget("EPRT", "|2|2001:db8::1|40000|", "2001:db8::1"); !ok || p != 40000 {
		t.Fatal("IPv6 EPRT rejected")
	}
	for _, arg := range []string{"|1|2001:db8::1|40000|", "|2|2001:db8::2|40000|", "|2|2001:db8::1|65536|", "|2|2001:db8::1|0|"} {
		if _, ok := ftpActiveTarget("EPRT", arg, "2001:db8::1"); ok {
			t.Fatal("invalid/bounce EPRT accepted", arg)
		}
	}
	for _, arg := range []string{"192,0,2,10,256,0", "192,0,2,10,0,0", "192,0,2,11,156,64", "192,0,2,10,156", "192,0,2,10,-1,64"} {
		if _, ok := ftpActiveTarget("PORT", arg, "192.0.2.10"); ok {
			t.Fatal("invalid/bounce PORT accepted", arg)
		}
	}
	f := newFTPTrace()
	for i := 0; i < 100; i++ {
		f.line(true, "NOOP\r\n")
	}
	e, _ := New(DefaultConfig())
	for _, ev := range f.events {
		if _, err := e.Observe(ev); err != nil {
			t.Fatal(err)
		}
	}
	flow := e.flows[flowKey(f.control)]
	if !flow.ftpDisabled || flow.ftp != nil || e.Stats().Overflow != 1 || len(e.ftpData) != 0 {
		t.Fatal("unbounded pipelining", flow, e.Stats())
	}
}

func TestFTPGrantCapacityAndControlCleanup(t *testing.T) {
	f := newFTPTrace()
	// Pipelined passive requests can leave multiple unconsumed negotiations.
	for i := 0; i < 4; i++ {
		f.line(true, "EPSV\r\n")
	}
	for i := 0; i < 4; i++ {
		f.line(false, fmt.Sprintf("229 Passive (|||%d|)\r\n", 40000+i))
	}
	c := DefaultConfig()
	c.MaxFlows = 1
	e, _ := New(c)
	for _, ev := range f.events {
		if _, err := e.Observe(ev); err != nil {
			t.Fatal(err)
		}
		if len(e.ftpData) > c.MaxFlows {
			t.Fatal("unbounded grants")
		}
	}
	if len(e.ftpData) != 1 || e.Stats().Overflow != 3 {
		t.Fatal(e.ftpData, e.Stats())
	}
	ev := f.control
	ev.Kind, ev.At = "end", f.at
	if _, err := e.Observe(ev); err != nil || len(e.ftpData) != 0 {
		t.Fatal("control close retained grant", e.ftpData, err)
	}
}

func TestSMTPRelayRolesAreDetectorSpecific(t *testing.T) {
	for _, mode := range []string{"unknown", "relay-only", "networks-only", "inbound-relay", "outbound-relay", "internal-relay", "external-to-external", "unlisted-spambot", "relay-other-port"} {
		t.Run(mode, func(t *testing.T) {
			c := DefaultConfig()
			if mode != "unknown" && mode != "networks-only" {
				c.SMTPRelays = []string{"198.51.100.10", "10.0.0.1"}
			}
			if mode != "unknown" && mode != "relay-only" {
				c.InternalNetworks = []string{"10.0.0.0/8"}
			}
			var events []Event
			for i := 1; i <= 15; i++ {
				ev := baseEvent("syn", i)
				ev.SrcIP, ev.DstIP, ev.DstPort = "198.51.100.10", fmt.Sprintf("10.0.1.%d", i), 25
				if mode == "outbound-relay" || mode == "internal-relay" {
					ev.SrcIP = "10.0.0.1"
				}
				if mode == "outbound-relay" || mode == "external-to-external" {
					ev.DstIP = fmt.Sprintf("198.51.100.%d", i+20)
				}
				if mode == "unlisted-spambot" {
					ev.SrcIP = "10.0.0.2"
				}
				if mode == "relay-other-port" {
					ev.DstPort = 22
				}
				events = append(events, ev)
			}
			alerts, stats := packetReplay(t, c, events)
			expected := mode == "inbound-relay" || mode == "outbound-relay" || mode == "internal-relay"
			if expected {
				if len(alerts) != 0 || stats.SMTPRelayExclusions != 15 {
					t.Fatal(alerts, stats)
				}
				return
			}
			want := 2
			if mode == "relay-other-port" {
				want = 1
			}
			if len(alerts) != want {
				t.Fatal("genuine/unqualified fanout lost", alerts, stats)
			}
			for _, a := range alerts {
				if a.Name == "smtp.fanout" && (!strings.Contains(a.MatchedRecord, "SMTP source role:") || a.Count != 11) {
					t.Fatal("missing roles or counts", a)
				}
			}
		})
	}
}

func TestSMTPRelayStillAllowsVerticalScansAndIntel(t *testing.T) {
	c := DefaultConfig()
	c.SMTPRelays, c.InternalNetworks = []string{"192.0.2.10"}, []string{"198.51.100.0/24"}
	c.Indicators = []Indicator{{Value: "198.51.100.10", Kind: "ip", Category: "c2", Source: "fixture", Version: "1", ValidFrom: 0, ValidUntil: 1 << 62}}
	var events []Event
	for i := 0; i < 20; i++ {
		ev := baseEvent("syn", i)
		ev.DstPort = uint16(20 + i)
		events = append(events, ev)
	}
	alerts, stats := packetReplay(t, c, events)
	seen := map[string]bool{}
	for _, a := range alerts {
		seen[a.Name] = true
	}
	if !seen["network.scan"] || !seen["intel.c2"] || stats.SMTPRelayExclusions != 1 {
		t.Fatal("SMTP role became a general bypass", seen, stats)
	}
}

func TestRoleConfigurationValidation(t *testing.T) {
	for _, mutate := range []func(*Config){
		func(c *Config) { c.SMTPRelays = []string{"smtp.example"} },
		func(c *Config) { c.SMTPRelays = []string{"fe80::1%en0"} },
		func(c *Config) { c.SMTPRelays = make([]string, 257) },
		func(c *Config) { c.InternalNetworks = []string{"192.0.2.1"} },
		func(c *Config) { c.InternalNetworks = make([]string, 257) },
	} {
		c := DefaultConfig()
		mutate(&c)
		if c.Validate() == nil {
			t.Fatal("accepted invalid roles", c)
		}
	}
}
