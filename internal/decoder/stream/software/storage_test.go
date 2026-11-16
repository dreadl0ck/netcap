package software

import (
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/dreadl0ck/netcap/internal/aggregate"
	"github.com/dreadl0ck/netcap/internal/decoder"
	decoderconfig "github.com/dreadl0ck/netcap/internal/decoder/config"
	"github.com/dreadl0ck/netcap/internal/decoder/db"
	"github.com/dreadl0ck/netcap/internal/decoder/stream/vulnerability"
	"github.com/dreadl0ck/netcap/internal/netio"
	"github.com/dreadl0ck/netcap/types"
	"github.com/gogo/protobuf/proto"
)

type softwareStorageWriter struct {
	netio.AuditRecordWriter
	records []*types.Software
}

func (w *softwareStorageWriter) Write(record proto.Message) error {
	w.records = append(w.records, proto.Clone(record).(*types.Software))
	return nil
}

func softwareStorageConfig(t *testing.T) {
	t.Helper()
	oldConfig, oldItems, oldCount := decoderconfig.Instance, Store.Items, storedSoftwareCount.Load()
	oldVuln, oldExploit := db.VulnerabilitiesIndex, db.ExploitsIndex
	decoderconfig.Instance = &decoderconfig.Config{}
	Store.Items = map[string]*AtomicSoftware{}
	storedSoftwareCount.Store(0)
	db.VulnerabilitiesIndex, db.ExploitsIndex = nil, nil
	t.Cleanup(func() {
		decoderconfig.Instance, Store.Items = oldConfig, oldItems
		storedSoftwareCount.Store(oldCount)
		db.VulnerabilitiesIndex, db.ExploitsIndex = oldVuln, oldExploit
	})
}

func TestStoredSoftwareMatchesMemoryWithFlowChurnAndCallbacks(t *testing.T) {
	softwareStorageConfig(t)
	run := func(state *aggregate.Store) []*types.Software {
		Store.Items = map[string]*AtomicSoftware{}
		storedSoftwareCount.Store(0)
		decoderconfig.Instance.AggregateStore = state
		for i := range 5000 {
			flow, cid := fmt.Sprintf("flow-%05d", i), fmt.Sprintf("cid-%05d", i)
			for range 2 {
				WriteHTTPSoftware([]*AtomicSoftware{{Software: &types.Software{Product: "fixture", Version: "1", ObservedHost: "192.0.2.1", ObservationRole: "client", Timestamp: 1, Flows: []string{flow}, CommunityIDs: []string{cid}, DeviceProfiles: []string{"profile", "profile"}, DPIResults: []string{"HTTP"}}}}, flow, cid)
			}
		}
		for i := range 128 {
			WriteSoftware([]*AtomicSoftware{{Software: &types.Software{Product: fmt.Sprintf("other-%03d", i), Version: strings.Repeat("1", 20), ObservedHost: "192.0.2.2", Flows: []string{"first"}}}}, nil)
		}
		if state != nil {
			if err := state.Do(func(tx *aggregate.Tx) error {
				wire, found, err := tx.Get("software/base/fixture/1/192.0.2.1/client")
				if err != nil {
					return err
				}
				s, err := decodeSoftware(wire)
				if err != nil {
					return err
				}
				if !found || len(wire) > 2048 || len(s.record.Flows) != 0 || len(s.record.CommunityIDs) != 0 || s.counts[0] != 5000 || s.counts[1] != 5000 {
					t.Fatal("hot Software row grew with memberships", len(wire), s.counts)
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		}
		WriteSoftware([]*AtomicSoftware{{Software: &types.Software{Product: "fixture", Version: "1", ObservedHost: "192.0.2.1", ObservationRole: "client"}}}, func(s *AtomicSoftware) {
			s.Lock()
			defer s.Unlock()
			s.Flows[0] = "changed"
			s.Flows = append(s.Flows, "callback-flow")
			s.CommunityIDs = s.CommunityIDs[:3]
			s.Notes = "callback retained"
		})
		if Store.Size() != 129 {
			t.Fatalf("software count = %d", Store.Size())
		}
		w := &softwareStorageWriter{}
		if err := Decoder.DeInit(&decoder.AbstractDecoder{Writer: w}); err != nil {
			t.Fatal(err)
		}
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
			got := run(state)
			if len(got) != len(want) {
				t.Fatalf("software rows = %d, want %d", len(got), len(want))
			}
			for i := range got {
				if !proto.Equal(got[i], want[i]) {
					t.Fatalf("software %d differs\ngot: %s\nwant: %s", i, got[i], want[i])
				}
			}
			if len(got[0].Flows) != 5001 || len(got[0].CommunityIDs) != 3 || got[0].Notes != "callback retained" {
				t.Fatal("fixture did not exercise ordered memberships and callback replacement")
			}
			if len(Store.Items) != 0 || state.Health().PeakBytes > limit || state.Health().DiskWrites == 0 {
				t.Fatal("Software escaped the bounded backing store", state.Health())
			}
			decoderconfig.Instance.AggregateStore = nil
		})
	}
}

func TestStoredSoftwareConcurrentMembershipAndSnapshotIsolation(t *testing.T) {
	softwareStorageConfig(t)
	state, err := aggregate.Open(t.TempDir(), 1024, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	decoderconfig.Instance.AggregateStore = state
	const workers, perWorker = 8, 128
	var wg sync.WaitGroup
	for worker := range workers {
		wg.Go(func() {
			for i := range perWorker {
				flow := fmt.Sprintf("%d-%d", worker, i)
				WriteHTTPSoftware([]*AtomicSoftware{{Software: &types.Software{Product: "concurrent", Version: "1", Flows: []string{flow}, CommunityIDs: []string{flow}}}}, flow, flow)
			}
		})
	}
	wg.Wait()
	var snapshot *types.Software
	if err := walkStoredSoftware(func(s *types.Software) error { snapshot = s; return nil }); err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Flows) != workers*perWorker || len(snapshot.CommunityIDs) != workers*perWorker || Store.Size() != 1 {
		t.Fatal("concurrent memberships lost", len(snapshot.Flows), len(snapshot.CommunityIDs), Store.Size())
	}
	snapshot.Flows[0], snapshot.Product = "stale change", "stale product"
	if err := walkStoredSoftware(func(s *types.Software) error {
		if s.Flows[0] == "stale change" || s.Product != "concurrent" {
			t.Fatal("snapshot mutation changed retained Software")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	ResetCaches()
	if Store.Size() != 0 {
		t.Fatal("reset retained Software count")
	}
	if err := walkStoredSoftware(func(*types.Software) error { t.Fatal("reset retained Software rows"); return nil }); err != nil {
		t.Fatal(err)
	}
}

func TestUserAgentCacheIsBoundedWithoutDroppingResults(t *testing.T) {
	UserAgentParserMutex.Lock()
	oldMap, oldOrder, oldBytes := UserAgentCache, userAgentOrder, userAgentCacheBytes
	UserAgentCache, userAgentOrder, userAgentCacheBytes = map[string]*userAgent{}, nil, 0
	UserAgentParserMutex.Unlock()
	t.Cleanup(func() {
		UserAgentParserMutex.Lock()
		UserAgentCache, userAgentOrder, userAgentCacheBytes = oldMap, oldOrder, oldBytes
		UserAgentParserMutex.Unlock()
	})
	first := "Mozilla/5.0 Firefox/123.0 00000000 " + strings.Repeat("x", 1024)
	parsed := LookupUserAgent(first)
	if parsed == nil || parsed.Vendor != "Firefox" {
		t.Fatal("fixture does not parse", parsed)
	}
	for i := 1; i < 1500; i++ {
		raw := fmt.Sprintf("Mozilla/5.0 Firefox/123.0 %08d %s", i, strings.Repeat("x", 1024))
		UserAgentParserMutex.Lock()
		cacheUserAgentLocked(raw, parsed)
		UserAgentParserMutex.Unlock()
		if userAgentCacheBytes > maxUserAgentCacheBytes || len(UserAgentCache) > maxUserAgentCacheEntries {
			t.Fatal("user-agent cache escaped bound", userAgentCacheBytes, len(UserAgentCache))
		}
	}
	if _, found := UserAgentCache[first]; found {
		t.Fatal("fixture did not evict old user agents")
	}
	if result := LookupUserAgent(first); result == nil || result.Vendor != "Firefox" {
		t.Fatal("evicted agent no longer parses", result)
	}
}

func TestStoredSoftwareLookupCanReenterBackingStore(t *testing.T) {
	softwareStorageConfig(t)
	state, err := aggregate.Open(t.TempDir(), 1, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	decoderconfig.Instance.AggregateStore = state
	db.VulnerabilitiesIndex = snapshotIndex{}
	oldWriter, oldCount := vulnerability.Decoder.Writer, vulnerability.Decoder.NumRecordsWritten
	vulnerability.ResetVulnStore()
	t.Cleanup(func() {
		vulnerability.Decoder.Writer, vulnerability.Decoder.NumRecordsWritten = oldWriter, oldCount
		vulnerability.ResetVulnStore()
	})
	called := false
	vulnerability.Decoder.Writer = snapshotWriter{write: func(record *types.Vulnerability) {
		called = true
		for i := range 128 {
			flow := fmt.Sprintf("later-%03d", i)
			WriteHTTPSoftware([]*AtomicSoftware{{Software: &types.Software{Product: "snapshot", Version: "1", ObservedHost: "10.0.0.2", Flows: []string{flow}, CommunityIDs: []string{flow}}}}, flow, flow)
		}
		if len(record.Software.Flows) != 1 || record.Software.Flows[0] != "first" {
			t.Fatal("lookup evidence aliases later updates")
		}
	}}
	WriteSoftware([]*AtomicSoftware{{Software: &types.Software{Product: "snapshot", Version: "1", ObservedHost: "10.0.0.2", Flows: []string{"first"}}}}, nil)
	if !called {
		t.Fatal("fixture did not exercise lookup writer")
	}
	if err := walkStoredSoftware(func(s *types.Software) error {
		if len(s.Flows) != 129 || !s.HasKnownVulnerabilities {
			t.Fatal("lookup merge overwrote concurrent observations", s)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestStoredPassiveSoftwareDoesNotInvokeCVELookups(t *testing.T) {
	softwareStorageConfig(t)
	state, err := aggregate.Open(t.TempDir(), 1, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	decoderconfig.Instance.AggregateStore = state
	db.VulnerabilitiesIndex = snapshotIndex{}
	oldWriter := vulnerability.Decoder.Writer
	t.Cleanup(func() { vulnerability.Decoder.Writer = oldWriter })
	vulnerability.Decoder.Writer = snapshotWriter{write: func(*types.Vulnerability) { t.Fatal("passive fingerprint invoked CVE lookup") }}
	item := &types.Software{Product: "snapshot", Version: strings.Repeat("1", 20), SourceName: "SSH fingerprint", Flows: []string{"initial"}}
	if StorePassiveSoftware([]*types.Software{item, item}) != 1 || Store.Size() != 1 || len(Store.Items) != 0 {
		t.Fatal("passive software bypassed bounded aggregation")
	}
	item.Flows[0] = "caller mutation"
	if err := walkStoredSoftware(func(s *types.Software) error {
		if s.Version != strings.Repeat("1", 20) || s.Flows[0] != "initial" || s.VulnerabilityAssessment != "" {
			t.Fatal("passive observation changed", s)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
