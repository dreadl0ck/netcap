package collector

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/internal/decoder/config"
	"github.com/dreadl0ck/netcap/internal/netio"
	"github.com/dreadl0ck/netcap/internal/networkdetect"
	"github.com/dreadl0ck/netcap/internal/resolvers"
	"github.com/dreadl0ck/netcap/types"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"go.uber.org/zap"
)

func TestRound2EpochZeroCollectorAggregation(t *testing.T) {
	root := t.TempDir()
	if export := os.Getenv("NETCAP_W76_FIXTURES"); export != "" {
		root = export
	}
	input := filepath.Join(root, "epoch-zero.pcap")
	writeBehaviorPCAP(t, input, []behaviorPacket{
		replayDNS(time.Unix(0, 0), "192.0.2.53", "api.telegram.org"),
		replayDNS(time.Unix(1, 0), "192.0.2.53", "api.telegram.org"),
		replayDNS(time.Unix(2, 0), "192.0.2.53", "api.telegram.org"),
	})
	var reference []*types.Alert
	for _, workers := range []int{1, 2, 4, 8} {
		t.Run(fmt.Sprint(workers), func(t *testing.T) {
			out := t.TempDir()
			dc := config.DefaultConfig.Clone()
			dc.Out, dc.Source, dc.IncludeDecoders, dc.Quiet = out, input, "Ethernet,IPv4,UDP,DNS,Alert", true
			c := New(Config{Workers: workers, PacketBufferSize: 100, BaseLayer: layers.LayerTypeEthernet, DecodeOptions: gopacket.Default, DecoderConfig: dc, ResolverConfig: resolvers.Config{}, NoPrompt: true, NoSignalHandling: true, OutDirPermission: 0700, NetworkDetection: true})
			if err := c.CollectPcap(input); err != nil {
				t.Fatal(err)
			}
			if err := c.GetNetworkDetectionError(); err != nil {
				t.Fatal(err)
			}
			r, err := netio.Open(filepath.Join(out, "Alert.ncap.gz"), 4096)
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			if _, err := r.ReadHeader(); err != nil {
				t.Fatal(err)
			}
			var alerts []*types.Alert
			for {
				a := new(types.Alert)
				if err := r.Next(a); err == io.EOF {
					break
				} else if err != nil {
					t.Fatal(err)
				}
				alerts = append(alerts, a)
			}
			if len(alerts) != 1 || alerts[0].Count != 3 || alerts[0].FirstSeen != 0 || alerts[0].Timestamp != 0 || alerts[0].LastSeen != 2e9 {
				t.Fatal("epoch/EOF aggregate not persisted", alerts)
			}
			if workers == 1 {
				reference = alerts
			} else if !reflect.DeepEqual(reference, alerts) {
				t.Fatal("worker-dependent aggregates")
			}
			data, err := os.ReadFile(filepath.Join(out, networkdetect.StatsFilename))
			if err != nil {
				t.Fatal(err)
			}
			var stats networkdetect.Stats
			if err := json.Unmarshal(data, &stats); err != nil {
				t.Fatal(err)
			}
			if stats.Events != 3 || stats.Matches != 3 || stats.Alerts != 1 || stats.PendingAggregates != 0 || stats.Error != "" || stats.Late != 0 {
				t.Fatal(stats)
			}
		})
	}
}

func TestRound2LiveAggregationDurableBeforeClose(t *testing.T) {
	dc := config.DefaultConfig.Clone()
	dc.Out, dc.Quiet = t.TempDir(), true
	c := New(Config{DecoderConfig: dc, NetworkDetection: true})
	c.log = zap.NewNop()
	if err := c.initNetworkDetection(); err != nil {
		t.Fatal(err)
	}
	defer c.detachRecordAnalysis()
	defer func() {
		if err := c.closeNetworkDetection(); err != nil {
			t.Error(err)
		}
	}()
	ev := networkdetect.Event{Scope: networkdetect.Scope{Sensor: "local", Interface: "live"}, Kind: "dns", SrcIP: "192.0.2.1", DstIP: "192.0.2.53", Name: "api.telegram.org"}
	for _, at := range []int64{0, 1e9, 2e9} {
		ev.At = at
		alerts, err := c.networkDetector.Observe(ev)
		if err != nil || len(alerts) != 0 {
			t.Fatal(alerts, err)
		}
	}
	c.flushAllDecoders()
	read := func() []*types.Alert {
		t.Helper()
		r, err := netio.Open(filepath.Join(dc.Out, "Alert.ncap.gz"), 4096)
		if err != nil {
			t.Fatal(err)
		}
		defer r.Close()
		if _, err := r.ReadHeader(); err != nil {
			t.Fatal(err)
		}
		var rows []*types.Alert
		for {
			a := new(types.Alert)
			if err := r.Next(a); err == io.EOF {
				return rows
			} else if err != nil {
				t.Fatal(err)
			}
			rows = append(rows, a)
		}
	}
	rows := read()
	if len(rows) != 1 || rows[0].Count != 3 || rows[0].FirstSeen != 0 || rows[0].LastSeen != 2e9 || !strings.Contains(rows[0].Notes, "flush=live") {
		t.Fatal(rows)
	}
	// A checkpoint must neither advance the capture watermark nor lose later matches.
	ev.At = 3e9
	if _, err := c.networkDetector.Observe(ev); err != nil {
		t.Fatal(err)
	}
	c.flushAllDecoders()
	c.flushAllDecoders()
	rows = read()
	if len(rows) != 2 || rows[1].Count != 1 || rows[1].AggregateKey != rows[0].AggregateKey || c.networkDetector.Stats().Late != 0 || c.GetNetworkDetectionError() != nil {
		t.Fatal(rows, c.networkDetector.Stats(), c.GetNetworkDetectionError())
	}
}

func TestRound2ApplicationAggregationWriter(t *testing.T) {
	dc := config.DefaultConfig.Clone()
	dc.Out = t.TempDir()
	c := New(Config{DecoderConfig: dc, NetworkDetection: true})
	if err := c.initNetworkDetection(); err != nil {
		t.Fatal(err)
	}
	defer c.detachRecordAnalysis()
	scope := networkdetect.Scope{Sensor: "fixture", Interface: "pcap"}
	c.recordScopes[endpoints("192.0.2.1", 40000, "198.51.100.1", 443)] = recordScope{Scope: scope, Key: "fixture"}
	// Decoder callbacks can arrive out of order; replay sorts capture time.
	for _, at := range []int64{2e9, 0, 1e9} {
		c.observeDecodedRecord(&types.HTTP{Timestamp: at, SrcIP: "192.0.2.1", DstIP: "198.51.100.1", SrcPort: 40000, DstPort: 443, Method: "GET", URL: "/", StatusCode: 200})
	}
	if err := c.closeNetworkDetection(); err != nil {
		t.Fatal(err)
	}
	r, err := netio.Open(filepath.Join(dc.Out, "Alert.ncap.gz"), 4096)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if _, err := r.ReadHeader(); err != nil {
		t.Fatal(err)
	}
	var a types.Alert
	if err := r.Next(&a); err != nil {
		t.Fatal(err)
	}
	if a.Name != "policy.http-on-443" || a.Count != 3 || a.FirstSeen != 0 || a.LastSeen != 2e9 {
		t.Fatal("sorted application aggregate lost", &a)
	}
	if err := r.Next(new(types.Alert)); err != io.EOF {
		t.Fatal("unexpected extra row", err)
	}
	stats, err := networkdetect.ReadStats(filepath.Join(dc.Out, networkdetect.StatsFilename))
	if err != nil || stats.ApplicationAlerts != 1 || stats.Matches != 3 || stats.Late != 0 || stats.PendingAggregates != 0 {
		t.Fatal(stats, err)
	}
}
