package networkdetect

import (
	"strings"
	"testing"
	"unsafe"

	"github.com/dreadl0ck/netcap/types"
)

func TestApplicationObservationOwnsBoundedText(t *testing.T) {
	backing := strings.Repeat("/private-parser-buffer", 1<<16)
	for _, path := range []string{backing, backing[:8]} {
		o, ok := Observation(&types.HTTP{Method: "GET", URL: path, Host: backing, CommunityID: backing, ReassemblyStatus: backing})
		if !ok || len(o.Path) > 1024 || len(o.Host) > 253 || len(o.CommunityID) > 128 || len(o.Qualification) > 256 {
			t.Fatal("unbounded queued observation")
		}
		if unsafe.StringData(o.Path) == unsafe.StringData(path) || unsafe.StringData(o.Host) == unsafe.StringData(backing) {
			t.Fatal("small observation pinned a whole parser allocation")
		}
	}
}

func TestApplicationScanClearsConsumedStringSlots(t *testing.T) {
	c := DefaultConfig()
	c.BeaconSamples = 0
	e := NewApplication(c)
	o := ApplicationObservation{Scope: Scope{Sensor: "test", Interface: "pcap"}, SrcIP: "192.0.2.1", DstIP: "198.51.100.1", DstPort: 80, Kind: "http", Method: "GET", Status: 404}
	for i := 0; i < 64; i++ {
		o.At, o.Path = int64(i), strings.Repeat("x", 1024)
		e.Observe(o)
	}
	o.At, o.Path = c.WindowNS+100, "/current"
	e.Observe(o)
	for _, scan := range e.scans {
		if len(scan.samples) != 1 || scan.samples[0].path != "/current" {
			t.Fatal("expired samples remained active")
		}
		for _, sample := range scan.samples[len(scan.samples):cap(scan.samples)] {
			if sample.path != "" {
				t.Fatal("consumed path remained referenced beyond slice length")
			}
		}
	}
}

func TestQualifiedHTTPBoundariesCannotBecomeBeaconEvidence(t *testing.T) {
	for _, qualification := range []string{"capture_loss_elsewhere", "locally-truncated", "response-end-not-observed", ""} {
		cfg := DefaultConfig()
		cfg.BeaconSamples = 4
		e := NewApplication(cfg)
		for i := range 8 {
			e.Observe(ApplicationObservation{At: int64(i) * 10e9, Scope: Scope{Sensor: "test", Interface: "pcap"}, Kind: "http", SrcIP: "192.0.2.1", DstIP: "198.51.100.1", DstPort: 80, Method: "GET", Host: "fixture.test", Path: "/periodic", Status: 200, Qualification: qualification})
		}
		alerts := e.Flush()
		if qualification != "" && (len(alerts) != 0 || len(e.beacons) != 0) {
			t.Fatal("qualified boundary became a complete transaction", qualification, alerts)
		}
		if qualification == "" && len(alerts) == 0 {
			t.Fatal("clean periodic transaction negative control did not alert")
		}
	}
}
