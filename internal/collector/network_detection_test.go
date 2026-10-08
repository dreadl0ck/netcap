package collector

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/dreadl0ck/netcap/internal/behavior"
	"github.com/dreadl0ck/netcap/internal/decoder/config"
	"github.com/dreadl0ck/netcap/internal/networkdetect"
	"github.com/dreadl0ck/netcap/internal/resolvers"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

func TestFlightSimCollectorReplay(t *testing.T) {
	root := filepath.Join("..", "networkdetect", "testdata")
	data, err := os.ReadFile(filepath.Join(root, "cases.json"))
	if err != nil {
		t.Fatal(err)
	}
	var corpus struct {
		Cases []struct {
			Name     string   `json:"name"`
			Expected []string `json:"expected"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(data, &corpus); err != nil {
		t.Fatal(err)
	}
	for _, tc := range corpus.Cases {
		for _, origin := range []string{"synthetic", "live"} {
			if origin == "live" && networkdetect.SyntheticOnlyCase(tc.Name) {
				continue
			}
			caseRoot := root
			if origin == "live" {
				caseRoot = filepath.Join(root, "live")
			}
			t.Run(origin+"/"+tc.Name, func(t *testing.T) {
				var reference []string
				for _, workers := range []int{1, 2, 4, 8} {
					t.Run(fmt.Sprint(workers), func(t *testing.T) {
						out := t.TempDir()
						input := filepath.Join(caseRoot, tc.Name+".pcap")
						dc := config.DefaultConfig.Clone()
						dc.Out, dc.Source, dc.IncludeDecoders, dc.Quiet = out, input, "Ethernet,IPv4,TCP,UDP,DNS,ICMPv4,Alert", true
						c := New(Config{Workers: workers, PacketBufferSize: 100, BaseLayer: layers.LayerTypeEthernet, DecodeOptions: gopacket.Default, DecoderConfig: dc, ResolverConfig: resolvers.Config{}, NoPrompt: true, NoSignalHandling: true, OutDirPermission: 0700, NetworkDetection: true, NetworkDetectionConfig: filepath.Join(caseRoot, "config.json")})
						c.SetBehaviorEngine(nil, behavior.Scope{Sensor: "qualification", Interface: "pcap"})
						if err := c.CollectPcap(input); err != nil {
							t.Fatal(err)
						}
						if err := c.GetNetworkDetectionError(); err != nil {
							t.Fatal(err)
						}
						semantics := replayAlertSemantics(t, out)
						if workers == 1 {
							reference = semantics
						} else if !reflect.DeepEqual(reference, semantics) {
							t.Fatal("worker count changed detection evidence")
						}
						seen := map[string]bool{}
						for _, s := range semantics {
							for _, want := range tc.Expected {
								if len(s) >= len(want) && s[:len(want)] == want {
									seen[want] = true
								}
							}
						}
						for _, want := range tc.Expected {
							if !seen[want] {
								t.Fatalf("missing %s: %v", want, semantics)
							}
						}
						if len(tc.Expected) == 0 && len(semantics) != 0 {
							t.Fatalf("benign alerts: %v", semantics)
						}
						statsData, err := os.ReadFile(filepath.Join(out, "NetworkDetection.json"))
						if err != nil {
							t.Fatal(err)
						}
						var stats networkdetect.Stats
						if err := json.Unmarshal(statsData, &stats); err != nil {
							t.Fatal(err)
						}
						if stats.Events == 0 || stats.Overflow != 0 || stats.Late != 0 || stats.Error != "" {
							t.Fatalf("unhealthy detector: %+v", stats)
						}
					})
				}
			})
		}
	}
}
