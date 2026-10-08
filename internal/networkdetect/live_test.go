package networkdetect

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/dreadl0ck/netcap/types"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
)

func TestFlightSimCapturedReplay(t *testing.T) {
	root := filepath.Join("testdata", "live")
	data, err := os.ReadFile(filepath.Join(root, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest struct {
		Revision string            `json:"revision"`
		SHA256   map[string]string `json:"sha256"`
	}
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatal(err)
	}
	if manifest.Revision != FlightSimRevision {
		t.Fatal("FlightSim revision drift")
	}
	for name, want := range manifest.SHA256 {
		data, err := os.ReadFile(filepath.Join(root, name))
		if err != nil {
			t.Fatal(err)
		}
		hash := sha256.Sum256(data)
		if hex.EncodeToString(hash[:]) != want {
			t.Fatalf("fixture hash changed: %s", name)
		}
	}
	c, err := LoadConfig(filepath.Join(root, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range corpus().Cases {
		if SyntheticOnlyCase(tc.Name) {
			continue
		}
		t.Run(tc.Name, func(t *testing.T) {
			log, err := os.ReadFile(filepath.Join(root, tc.Name+".log"))
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(log), "ERROR:") || strings.Contains(string(log), "FATAL:") || !strings.Contains(string(log), "Done (") {
				t.Fatalf("failed FlightSim module: %s", log)
			}
			f, err := os.Open(filepath.Join(root, tc.Name+".pcap"))
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			reader, err := pcapgo.NewReader(f)
			if err != nil {
				t.Fatal(err)
			}
			e, _ := New(c)
			var alerts []*types.Alert
			var events []Event
			for {
				data, info, err := reader.ReadPacketData()
				if err == io.EOF {
					break
				}
				if err != nil {
					t.Fatal(err)
				}
				packet := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.Default)
				packet.Metadata().CaptureInfo = info
				for _, ev := range PacketEvents(packet, Scope{Sensor: "qualification", Interface: "pcap"}) {
					events = append(events, ev)
					got, err := e.Observe(ev)
					if err != nil {
						t.Fatal(err)
					}
					alerts = append(alerts, got...)
				}
			}
			for _, want := range tc.Expected {
				found := false
				for _, alert := range alerts {
					found = found || alert.RuleName == want
				}
				if !found {
					t.Fatalf("captured %s missing %s: alerts=%+v stats=%+v", tc.Name, want, alerts, e.Stats())
				}
			}
			stats := e.Stats()
			if stats.Events == 0 || stats.Overflow != 0 || stats.Late != 0 {
				t.Fatalf("bad capture stats: %+v", stats)
			}
			if !reflect.DeepEqual(alerts, replay(t, c, events)) {
				t.Fatal("live fixture replay changed")
			}
			if os.Getenv("NETCAP_NETWORK_EXPECTATIONS") != "1" {
				data, err := os.ReadFile(filepath.Join(root, tc.Name+".alerts.json"))
				if err != nil {
					t.Fatal(err)
				}
				var expected []*types.Alert
				if err := json.Unmarshal(data, &expected); err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(alerts, expected) {
					t.Fatal("captured alert evidence changed; review before updating")
				}
			}
			if os.Getenv("NETCAP_NETWORK_EXPECTATIONS") == "1" {
				data, err := json.MarshalIndent(alerts, "", "  ")
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(root, tc.Name+".alerts.json"), append(data, '\n'), 0644); err != nil {
					t.Fatal(err)
				}
			}
			t.Logf("%s: events=%d alerts=%d streamGaps=%d", tc.Name, stats.Events, stats.Alerts, stats.StreamGaps)
		})
	}
}
