package service

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/internal/aggregate"
	"github.com/dreadl0ck/netcap/internal/decoder"
	decoderconfig "github.com/dreadl0ck/netcap/internal/decoder/config"
	"github.com/dreadl0ck/netcap/internal/decoder/db"
	"github.com/dreadl0ck/netcap/internal/decoder/stream/software"
	"github.com/dreadl0ck/netcap/internal/netio"
	"github.com/dreadl0ck/netcap/internal/vulndb"
	"github.com/dreadl0ck/netcap/types"
	"github.com/gogo/protobuf/proto"
)

type serviceTestWriter struct {
	netio.AuditRecordWriter
	records []*types.Service
}

func (w *serviceTestWriter) Write(record proto.Message) error {
	w.records = append(w.records, proto.Clone(record).(*types.Service))
	return nil
}

func serviceStorageConfig(t *testing.T) {
	t.Helper()
	old := decoderconfig.Instance
	decoderconfig.Instance = &decoderconfig.Config{Quiet: true}
	ResetStore()
	t.Cleanup(func() { decoderconfig.Instance.AggregateStore = nil; ResetStore(); decoderconfig.Instance = old })
}

func TestStoredServicesPreserveRepresentativeAndFlowMembership(t *testing.T) {
	serviceStorageConfig(t)
	run := func(state *aggregate.Store) []*types.Service {
		decoderconfig.Instance.AggregateStore = nil
		ResetStore()
		decoderconfig.Instance.AggregateStore = state
		for i := 0; i < 5000; i++ {
			banner := []byte("short")
			if i%3 == 1 {
				banner = []byte("HTTP/1.1 200 OK\r\n\r\n")
			}
			if i%3 == 2 {
				banner = []byte("HTTP/1.1 200 OK\r\nX-Review: longer\r\n\r\n")
			}
			o := Observation{ID: "shared", FlowID: fmt.Sprintf("flow-%05d", i), IP: "192.0.2.10", Port: 80, Protocol: "TCP", Timestamp: int64(i + 1), ServerBytes: len(banner), ClientBytes: 20, Banner: banner}
			if _, err := ObserveBanner(o); err != nil {
				t.Fatal(err)
			}
			if _, err := ObserveBanner(o); err != nil {
				t.Fatal(err)
			}
		}
		AddApplications("shared", []string{"http", "tls", "http"})
		for i := 0; i < 128; i++ {
			if _, err := ObserveBanner(Observation{ID: fmt.Sprintf("other-%03d", i), FlowID: "fixture", Protocol: "UDP", Port: 9999}); err != nil {
				t.Fatal(err)
			}
		}
		if Store.Size() != 129 {
			t.Fatal("service count differs", Store.Size())
		}
		w := &serviceTestWriter{}
		if err := Decoder.DeInit(&decoder.AbstractDecoder{Writer: w}); err != nil {
			t.Fatal(err)
		}
		sort.Slice(w.records, func(i, j int) bool { return w.records[i].Banner < w.records[j].Banner })
		return w.records
	}
	want := run(nil)
	for _, limit := range []int64{1, 2048, 1 << 20} {
		t.Run(fmt.Sprint(limit), func(t *testing.T) {
			state, err := aggregate.Open(t.TempDir(), limit, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer state.Close()
			defer func() { decoderconfig.Instance.AggregateStore = nil }()
			got := run(state)
			if len(got) != len(want) {
				t.Fatal("service rows lost")
			}
			for i := range got {
				if !proto.Equal(got[i], want[i]) {
					t.Fatalf("service %d differs\ngot: %s\nwant: %s", i, got[i], want[i])
				}
			}
			last := got[len(got)-1]
			if len(last.Flows) != 5000 || last.MatchedProbeID == "" || last.DetectedProtocolName != "HTTP" {
				t.Fatal("fixture did not exercise flow union, probing and protocol labels", last)
			}
			if err = state.Do(func(tx *aggregate.Tx) error {
				wire, _, err := tx.Get("service/base/shared")
				if err != nil {
					return err
				}
				var s types.Service
				if err = proto.Unmarshal(wire, &s); err != nil {
					return err
				}
				if len(s.Flows) > 0 || len(s.Applications) > 0 {
					return fmt.Errorf("growing service sets stayed in hot record")
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			if h := state.Health(); h.PeakBytes > limit || h.DiskWrites == 0 || limit > 256 && h.Evictions == 0 {
				t.Fatal(h)
			}
		})
	}
}

func TestStoredServicesConcurrentObservations(t *testing.T) {
	serviceStorageConfig(t)
	state, err := aggregate.Open(t.TempDir(), 2048, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	defer func() { decoderconfig.Instance.AggregateStore = nil }()
	decoderconfig.Instance.AggregateStore = state
	var wg sync.WaitGroup
	for worker := 0; worker < 8; worker++ {
		wg.Go(func() {
			for i := 0; i < 100; i++ {
				if _, err := ObserveBanner(Observation{ID: "shared", FlowID: fmt.Sprintf("%d/%d", worker, i), Banner: []byte("fixture"), Timestamp: 1}); err != nil {
					t.Error(err)
				}
				AddApplications("shared", []string{fmt.Sprint(worker)})
			}
		})
	}
	wg.Wait()
	w := &serviceTestWriter{}
	if err = Decoder.DeInit(&decoder.AbstractDecoder{Writer: w}); err != nil {
		t.Fatal(err)
	}
	if len(w.records) != 1 || len(w.records[0].Flows) != 800 || len(w.records[0].Applications) != 8 || Store.Size() != 1 {
		t.Fatal("concurrent service updates lost membership")
	}
	ResetStore()
	if Store.Size() != 0 {
		t.Fatal("reset retained stored services")
	}
}

type probeReentryIndex struct {
	state  *aggregate.Store
	called *bool
}

func (p probeReentryIndex) Vulnerabilities(_, _, _ string) ([]vulndb.Vulnerability, error) {
	*p.called = true
	return nil, p.state.Do(func(tx *aggregate.Tx) error { return tx.Put("probe/callback", []byte("observed")) })
}
func (probeReentryIndex) Exploits(_, _, _ string) ([]vulndb.Exploit, error) { return nil, nil }
func (probeReentryIndex) Close() error                                      { return nil }

func TestServiceProbeCanReenterAggregateStore(t *testing.T) {
	if os.Getenv("NETCAP_SERVICE_PROBE_CHILD") == "" {
		exe, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, exe, "-test.run=^TestServiceProbeCanReenterAggregateStore$", "-test.count=1", "-test.timeout=6s")
		cmd.Env = append(os.Environ(), "NETCAP_SERVICE_PROBE_CHILD=1")
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("probe callback deadlocked or failed: %v\n%s", err, output)
		}
		return
	}
	serviceStorageConfig(t)
	state, err := aggregate.Open(t.TempDir(), 2048, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	defer func() { decoderconfig.Instance.AggregateStore = nil }()
	decoderconfig.Instance.AggregateStore = state
	oldIndex, oldExploits, oldItems := db.VulnerabilitiesIndex, db.ExploitsIndex, software.Store.Items
	defer func() {
		db.VulnerabilitiesIndex, db.ExploitsIndex, software.Store.Items = oldIndex, oldExploits, oldItems
	}()
	called := false
	db.VulnerabilitiesIndex = probeReentryIndex{state, &called}
	db.ExploitsIndex = nil
	software.Store.Items = map[string]*software.AtomicSoftware{}
	if _, err = ObserveBanner(Observation{ID: "fixture", FlowID: "flow", IP: "192.0.2.10", Port: 80, Protocol: "TCP", Banner: []byte("HTTP/1.1 200 OK\r\nServer: Fixture/1\r\n\r\n")}); err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Fatal("service signature did not emit a software lookup")
	}
}
