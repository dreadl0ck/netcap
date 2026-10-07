package networkdetect

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/dreadl0ck/netcap/types"
)

type fixtureCase struct {
	Name     string   `json:"name"`
	Events   []Event  `json:"events"`
	Expected []string `json:"expected"`
}
type fixtureCorpus struct {
	Contract int           `json:"contract"`
	Origin   string        `json:"origin"`
	Revision string        `json:"revision"`
	Config   Config        `json:"config"`
	Cases    []fixtureCase `json:"cases"`
}

func baseEvent(kind string, n int) Event {
	return Event{At: 1800000000000000000 + int64(n)*100000000, Scope: Scope{Sensor: "qualification", Interface: "pcap"}, Kind: kind, SrcIP: "192.0.2.10", DstIP: "198.51.100.10", SrcPort: 40000, DstPort: 443}
}
func corpus() fixtureCorpus {
	c := DefaultConfig()
	c.SSHBytes = 4096
	for _, category := range []string{"c2", "sink", "imposter"} {
		c.Indicators = append(c.Indicators, Indicator{Value: category + ".example", Kind: "domain", Category: category, Source: "synthetic qualification", Version: "1", ValidFrom: 1799999999000000000, ValidUntil: 1800000100000000000})
	}
	result := fixtureCorpus{Contract: 1, Origin: "synthetic source-shape fixtures; not captured FlightSim executions", Revision: FlightSimRevision, Config: c}
	for _, category := range []string{"c2", "sink", "imposter"} {
		ev := baseEvent("dns", 0)
		ev.Name = category + ".example"
		ev.QType = 1
		result.Cases = append(result.Cases, fixtureCase{category, []Event{ev}, []string{"intel." + category}})
	}
	var dga, tunnel, scan, smtp, icmp []Event
	for n := 0; n < 10; n++ {
		ev := baseEvent("dns", n)
		ev.Name = fmt.Sprintf("q%dazwsxe.com", n)
		ev.QType = 1
		dga = append(dga, ev)
		ev.Name = fmt.Sprintf("qazwsxedcrfvtgbyhnujmikolp%d0123.tunnel.example", n)
		ev.QType = 16
		tunnel = append(tunnel, ev)
		ev = baseEvent("syn", n)
		ev.DstPort = uint16(80 + n)
		scan = append(scan, ev)
		ev.DstPort = 25
		ev.DstIP = fmt.Sprintf("198.51.100.%d", n+1)
		smtp = append(smtp, ev)
		ev = baseEvent("icmp", n)
		ev.Seq = uint32(n)
		ev.Payload = make([]byte, 1400)
		for i := range ev.Payload {
			ev.Payload[i] = byte(i)
		}
		icmp = append(icmp, ev)
	}
	result.Cases = append(result.Cases, fixtureCase{"dga", dga, []string{"dns.dga"}}, fixtureCase{"tunnel-dns", tunnel, []string{"dns.tunnel"}}, fixtureCase{"scan", scan, []string{"network.scan"}}, fixtureCase{"spambot", smtp, []string{"smtp.fanout", "network.scan"}}, fixtureCase{"tunnel-icmp", icmp, []string{"icmp.tunnel"}})
	for _, tc := range []struct {
		name, payload, detector string
		port                    uint16
	}{{"miner", `{"jsonrpc":"2.0","method":"mining.subscribe","params":[]}` + "\n", "protocol.stratum", 3333}, {"irc", "NICK analyst\r\nUSER analyst 0 * :training\r\n", "protocol.irc", 6667}, {"cleartext", strings.Repeat("q", 1000), "policy.cleartext-service", 23}} {
		syn := baseEvent("syn", 0)
		syn.DstPort = tc.port
		syn.Seq = 99
		ev := syn
		ev.At++
		ev.Kind = "data"
		ev.Seq = 100
		ev.Payload = []byte(tc.payload)
		result.Cases = append(result.Cases, fixtureCase{tc.name, []Event{syn, ev}, []string{tc.detector}})
	}
	for _, port := range []uint16{22, 443} {
		syn := baseEvent("syn", 0)
		syn.DstPort = port
		syn.Seq = 99
		banner := syn
		banner.At++
		banner.Kind = "data"
		banner.Seq = 100
		banner.Payload = []byte("SSH-2.0-test\r\n")
		data := banner
		data.At++
		data.Seq += uint32(len(banner.Payload))
		data.Payload = make([]byte, 4096)
		name := "ssh-transfer"
		expected := []string{"ssh.large-upload"}
		if port != 22 {
			name = "ssh-exfil"
			expected = []string{"ssh.nonstandard-port", "ssh.large-upload"}
		}
		result.Cases = append(result.Cases, fixtureCase{name, []Event{syn, banner, data}, expected})
	}
	for _, tc := range []struct{ name, domain, detector string }{{"oast", "random.oast.pro", "policy.oast"}, {"telegram-bot", "api.telegram.org", "policy.telegram-api"}} {
		ev := baseEvent("dns", 0)
		ev.Name = tc.domain
		ev.QType = 1
		result.Cases = append(result.Cases, fixtureCase{tc.name, []Event{ev}, []string{tc.detector}})
	}
	var benign []Event
	for n := 0; n < 15; n++ {
		ev := baseEvent("dns", n)
		ev.Name = "www.example.com"
		ev.QType = 16
		benign = append(benign, ev)
		ev.Kind = "syn"
		ev.Name = ""
		ev.DstPort = 443
		benign = append(benign, ev)
		ev.Kind = "icmp"
		ev.Seq = uint32(n)
		ev.Payload = make([]byte, 1400)
		benign = append(benign, ev)
	}
	result.Cases = append(result.Cases, fixtureCase{"benign", benign, []string{}})
	return result
}

func replay(t *testing.T, c Config, events []Event) []*types.Alert {
	t.Helper()
	e, err := New(c)
	if err != nil {
		t.Fatal(err)
	}
	var alerts []*types.Alert
	for _, ev := range events {
		got, err := e.Observe(ev)
		if err != nil {
			t.Fatal(err)
		}
		alerts = append(alerts, got...)
	}
	return alerts
}

func TestFlightSimSourceShapeContract(t *testing.T) {
	fixture := corpus()
	for _, tc := range fixture.Cases {
		t.Run(tc.Name, func(t *testing.T) {
			alerts := replay(t, fixture.Config, tc.Events)
			seen := map[string]bool{}
			for _, alert := range alerts {
				seen[alert.RuleName] = true
				var evidence Evidence
				if err := json.Unmarshal([]byte(alert.MatchedRecord), &evidence); err != nil {
					t.Fatal(err)
				}
				if evidence.Schema != 1 || evidence.FirstSeen > evidence.LastSeen || len(evidence.Samples) > 8 {
					t.Fatalf("invalid evidence: %+v", evidence)
				}
			}
			for _, want := range tc.Expected {
				if !seen[want] {
					t.Fatalf("missing %s: %+v", want, seen)
				}
				delete(seen, want)
			}
			if len(seen) > 0 {
				t.Fatalf("unexpected detections: %+v", seen)
			}
			if !reflect.DeepEqual(alerts, replay(t, fixture.Config, tc.Events)) {
				t.Fatal("nondeterministic replay")
			}
		})
	}
	if export := os.Getenv("NETCAP_NETWORK_FIXTURES"); export != "" {
		data, err := json.MarshalIndent(fixture, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		data = append(data, '\n')
		if err := os.MkdirAll(export, 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(export, "cases.json"), data, 0644); err != nil {
			t.Fatal(err)
		}
		hash := sha256.Sum256(data)
		if err := os.WriteFile(filepath.Join(export, "cases.sha256"), []byte(hex.EncodeToString(hash[:])+"\n"), 0644); err != nil {
			t.Fatal(err)
		}
	}
}

func TestIsolationExpiryRetransmissionsAndBounds(t *testing.T) {
	c := DefaultConfig()
	c.ScanTargets = 2
	e, _ := New(c)
	a := baseEvent("syn", 0)
	a.DstPort = 80
	for n := 0; n < 100; n++ {
		a.At++
		alerts, err := e.Observe(a)
		if err != nil || len(alerts) != 0 {
			t.Fatalf("retransmissions: %v %v", alerts, err)
		}
	}
	b := a
	b.At++
	b.DstPort = 81
	b.Scope.VLANs = []uint16{2}
	if got, _ := e.Observe(b); len(got) != 0 {
		t.Fatal("cross-scope correlation")
	}
	b.Scope = a.Scope
	b.SrcIP = "192.0.2.11"
	b.At++
	if got, _ := e.Observe(b); len(got) != 0 {
		t.Fatal("cross-host correlation")
	}
	b.SrcIP = a.SrcIP
	b.At = a.At + c.WindowNS + 1
	if got, _ := e.Observe(b); len(got) != 0 {
		t.Fatal("expired ports counted")
	}
	b.At--
	if got, _ := e.Observe(b); len(got) != 0 || e.Stats().Late != 1 {
		t.Fatal("late event accepted")
	}
	c.MaxKeys = 2
	c.MaxFlows = 2
	e, _ = New(c)
	for n := 0; n < 1000; n++ {
		ev := baseEvent("syn", n)
		ev.At = baseEvent("syn", 0).At + int64(n)
		ev.SrcIP = fmt.Sprintf("192.0.%d.%d", n/254, n%254+1)
		_, _ = e.Observe(ev)
	}
	s := e.Stats()
	if s.Keys > 2 || s.Flows > 2 || s.Overflow == 0 {
		t.Fatalf("unbounded state: %+v", s)
	}
}

func TestStreamSegmentationAndGaps(t *testing.T) {
	c := DefaultConfig()
	syn := baseEvent("syn", 0)
	syn.Seq = 99
	syn.DstPort = 3333
	a := syn
	a.Kind = "data"
	a.At++
	a.Seq = 100
	a.Payload = []byte(`{"method":"mining.`)
	b := a
	b.At++
	b.Seq += uint32(len(a.Payload))
	b.Payload = []byte("subscribe\"}\n")
	if alerts := replay(t, c, []Event{syn, a, b}); len(alerts) != 1 || alerts[0].RuleName != "protocol.stratum" {
		t.Fatal("segmented Stratum not detected")
	}
	b.Seq++
	if alerts := replay(t, c, []Event{syn, a, b}); len(alerts) != 0 {
		t.Fatal("signature assembled across gap")
	}
}

func TestIndicatorValidityExceptionsAndSuffixBoundary(t *testing.T) {
	c := corpus().Config
	ev := baseEvent("dns", 0)
	ev.Name = "notc2.example"
	ev.QType = 1
	if alerts := replay(t, c, []Event{ev}); len(alerts) != 0 {
		t.Fatal("substring indicator match")
	}
	ev.Name = "x.c2.example"
	if alerts := replay(t, c, []Event{ev}); len(alerts) != 1 {
		t.Fatal("subdomain indicator missing")
	}
	ev.At = c.Indicators[0].ValidUntil
	if alerts := replay(t, c, []Event{ev}); len(alerts) != 0 {
		t.Fatal("expired indicator")
	}
	ev = baseEvent("dns", 0)
	ev.Name = "c2.example"
	c.ApprovedSources = []string{"192.0.2.0/24"}
	if alerts := replay(t, c, []Event{ev}); len(alerts) != 0 {
		t.Fatal("authorized source not exempted")
	}
}

func TestIPv6IndicatorAndSourceNormalization(t *testing.T) {
	c := DefaultConfig()
	ev := baseEvent("syn", 0)
	ev.SrcIP = "2001:db8::1"
	ev.DstIP = "2001:db8::2"
	c.Indicators = []Indicator{{Value: "2001:DB8::2", Kind: "ip", Category: "c2", Source: "fixture", Version: "1", ValidFrom: 1, ValidUntil: 2000000000000000000}}
	if got := replay(t, c, []Event{ev}); len(got) != 1 || got[0].RuleName != "intel.c2" {
		t.Fatal("IPv6 indicator normalization failed")
	}
	c.ApprovedSources = []string{"2001:DB8::1"}
	if got := replay(t, c, []Event{ev}); len(got) != 0 {
		t.Fatal("IPv6 exception normalization failed")
	}
}
