package rules

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"math/rand"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gogo/protobuf/proto"

	"github.com/dreadl0ck/netcap/internal/delimited"
	"github.com/dreadl0ck/netcap/internal/evidence"
	"github.com/dreadl0ck/netcap/types"
)

func offlineTestPack(count int) *OfflinePack {
	return &OfflinePack{Format: OfflineFormat, Rules: []OfflineRule{{ID: "syn", Name: "Grouped SYN", Type: "TCP", Expression: "SYN && DstPort == 80", Severity: "high", Enabled: true, Threshold: OfflineThreshold{Count: count, Window: "600s", GroupBy: []string{"SrcIP", "DstIP", "DstPort"}}}}}
}

func offlineTestWrite(t *testing.T, path string, b []byte) {
	t.Helper()
	if err := os.WriteFile(path, b, 0600); err != nil {
		t.Fatal(err)
	}
}
func offlineTestJSON(t *testing.T, dir, name string, v any) {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	offlineTestWrite(t, filepath.Join(dir, name), b)
}
func offlineTestDirectory(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	m := evidence.CaptureManifest{Version: 1, RunID: "test-run", Status: "complete", Config: evidence.CaptureConfig{Kind: "file"}, CommunityScopes: &evidence.ScopeLedger{Schema: 1, Complete: true, Entries: []evidence.CommunityScope{{CommunityID: "1:test", Scope: evidence.FlowScope{Sensor: "local", InterfaceIndex: 0, VLANs: []uint16{}}}}}}
	offlineTestJSON(t, dir, "capture-manifest.json", m)
	offlineTestJSON(t, dir, OfflineReadyFile, OfflineReadyMarker{1, "test-run"})
	return dir
}
func offlineTestRecords(t *testing.T, dir, typ string, gz bool, records []proto.Message) {
	t.Helper()
	var b bytes.Buffer
	w := delimited.NewWriter(&b)
	if err := w.PutProto(&types.Header{Type: offlineType(typ)}); err != nil {
		t.Fatal(err)
	}
	for _, r := range records {
		if err := w.PutProto(r); err != nil {
			t.Fatal(err)
		}
	}
	name := typ + ".ncap"
	data := b.Bytes()
	if gz {
		var z bytes.Buffer
		g := gzip.NewWriter(&z)
		if _, err := g.Write(data); err != nil {
			t.Fatal(err)
		}
		if err := g.Close(); err != nil {
			t.Fatal(err)
		}
		data = z.Bytes()
		name += ".gz"
	}
	offlineTestWrite(t, filepath.Join(dir, name), data)
}
func offlineTestTCP(n int) []proto.Message {
	r := make([]proto.Message, n)
	for i := range r {
		r[i] = &types.TCP{Timestamp: int64(time.Second) + int64(i), SrcIP: "192.0.2.1", DstIP: "192.0.2.2", DstPort: 80, SYN: true, CommunityID: "1:test"}
	}
	return r
}
func offlineTestEval(t *testing.T, dir string, p *OfflinePack) *OfflineReport {
	t.Helper()
	r, err := EvaluateOffline(context.Background(), OfflineRequest{Directory: dir, Pack: p})
	if err != nil {
		t.Fatal(err)
	}
	return r
}
func offlineTestAlerts(t *testing.T, dir string) []*types.Alert {
	t.Helper()
	f, err := os.Open(filepath.Join(dir, "Alert.ncap.gz"))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	g, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	reader := delimited.NewReaderWithLimit(g, 16<<20)
	var h types.Header
	if err := reader.NextProto(&h); err != nil {
		t.Fatal(err)
	}
	var alerts []*types.Alert
	for {
		a := &types.Alert{}
		err := reader.NextProto(a)
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			t.Fatal(err)
		}
		alerts = append(alerts, a)
	}
	return alerts
}

func TestOfflineStrictPack(t *testing.T) {
	good := `format: netcap-offline-rules/v1
rules:
  - id: grouped
    name: SYN group
    type: TCP
    expression: SYN && DstPort in [80, 443]
    severity: high
    enabled: true
    threshold:
      count: 50
      window: 600s
      group_by: [SrcIP, DstIP, DstPort]
`
	if _, err := ParseOfflinePack([]byte(good)); err != nil {
		t.Fatal(err)
	}
	if _, err := ParseOfflinePack([]byte(good + "---\n{}\n")); err == nil {
		t.Fatal("multiple docs admitted")
	}
	for _, bad := range []string{
		strings.Replace(good, "id: grouped", "id: ../bad", 1), strings.Replace(good, "count: 50", "count: 1", 1), strings.Replace(good, "window: 600s", "window: 721h", 1), strings.Replace(good, "SrcIP, DstIP", "SrcIP, src_ip", 1), strings.Replace(good, "SrcIP, DstIP", "SrcIP, SrcIP", 1), strings.Replace(good, "expression: SYN && DstPort in [80, 443]", "expression: DurationSince(Timestamp) > 0", 1), strings.Replace(good, "expression: SYN && DstPort in [80, 443]", "expression: now() != nil", 1), strings.Replace(good, "    threshold:", "    actions: []\n    threshold:", 1), strings.Replace(good, "    threshold:", "    sequence: {}\n    threshold:", 1), strings.Replace(good, "    threshold:", "    distinct: true\n    threshold:", 1), strings.Replace(good, "count: 50", "count: 50\n      count: 51", 1),
	} {
		if _, err := ParseOfflinePack([]byte(strings.Replace(bad, "enabled: true", "enabled: false", 1))); err == nil || strings.Contains(err.Error(), "at least one enabled rule") {
			t.Fatalf("invalid disabled rule admitted: %s", bad)
		}
	}
	path := filepath.Join(t.TempDir(), "offline.yaml")
	offlineTestWrite(t, path, []byte(good))
	if _, err := LoadRulesFromFile(path); err == nil || !strings.Contains(err.Error(), "net investigate rules -read OUT -rules FILE") {
		t.Fatal("legacy loader did not reject offline format with guidance", err)
	}
	if _, err := LoadOfflinePack(path); err != nil {
		t.Fatal(err)
	}
}

func TestOfflineGroupThresholdResetAndMetadata(t *testing.T) {
	for _, compressed := range []bool{false, true} {
		t.Run(map[bool]string{false: "plain", true: "gzip"}[compressed], func(t *testing.T) {
			dir := offlineTestDirectory(t)
			records := offlineTestTCP(100)
			offlineTestRecords(t, dir, "TCP", compressed, records)
			r := offlineTestEval(t, dir, offlineTestPack(50))
			if r.Status != "complete" || r.CommittedAlerts != 2 || r.PlannedAlerts != 2 || r.Rules[0].Matches != 100 {
				t.Fatalf("report: %+v", r)
			}
			alerts := offlineTestAlerts(t, dir)
			if len(alerts) != 2 {
				t.Fatal(len(alerts))
			}
			for i, a := range alerts {
				var notes map[string]OfflineAlertMetadata
				if err := json.Unmarshal([]byte(a.Notes), &notes); err != nil {
					t.Fatal(err)
				}
				m := notes["netcapOffline"]
				if m.Count != 50 || len(m.Contributors) != 16 || !m.ContributorsTruncated || m.Contributors[0].Ordinal != uint64(i*50) || m.Contributors[15].Ordinal != uint64(i*50+49) || len(m.EventID) != 64 || m.RuleID != "syn" || m.RuleDigest != a.RuleDigest || m.InputCanonicalDigest != r.InputCanonicalDigest {
					t.Fatalf("metadata: %+v", m)
				}
				for _, contributor := range m.Contributors {
					found := false
					for _, source := range r.Files {
						found = found || source.Name == contributor.File && source.SHA256 == contributor.FileSHA256 && contributor.FileSHA256 != ""
					}
					if !found {
						t.Fatalf("contributor lacks verified source-file identity: %+v", contributor)
					}
				}
				b, _ := json.Marshal(records[i*50+49])
				if a.MatchedRecord != string(b) || a.MatchedRecordSHA256 != offlineHash(b) {
					t.Fatal("trigger record changed")
				}
			}
			listed, err := ListOfflineEvaluations(dir)
			if err != nil || len(listed) != 1 || listed[0].CommittedAlerts != 2 {
				t.Fatalf("list: %+v %v", listed, err)
			}
			info, err := os.Stat(filepath.Join(dir, "rule-evaluations", r.ID+".json"))
			if err != nil || info.Mode().Perm() != 0600 {
				t.Fatal("report permissions", err)
			}
		})
	}
	dir := offlineTestDirectory(t)
	records := offlineTestTCP(50)
	for i := 25; i < 50; i++ {
		records[i].(*types.TCP).SrcIP = "192.0.2.3"
	}
	offlineTestRecords(t, dir, "TCP", true, records)
	if r := offlineTestEval(t, dir, offlineTestPack(50)); r.CommittedAlerts != 0 {
		t.Fatal("mixed distinct group counts")
	}
}

func TestOfflineInclusiveWindow(t *testing.T) {
	for _, delta := range []int64{0, 1} {
		t.Run(time.Duration(delta).String(), func(t *testing.T) {
			dir := offlineTestDirectory(t)
			records := offlineTestTCP(2)
			records[1].(*types.TCP).Timestamp = int64(time.Second) + int64(600*time.Second) + delta
			offlineTestRecords(t, dir, "TCP", false, records)
			r := offlineTestEval(t, dir, offlineTestPack(2))
			want := int64(1)
			if delta == 1 {
				want = 0
			}
			if r.CommittedAlerts != want {
				t.Fatalf("boundary delta=%d: %+v", delta, r)
			}
		})
	}
}

func TestOfflineDeterministicShuffleDuplicatesAndMaps(t *testing.T) {
	pack := offlineTestPack(2)
	pack.Rules[0].Type = "HTTP"
	pack.Rules[0].Expression = `Host contains "test"`
	pack.Rules[0].Threshold.GroupBy = []string{"Host", "DstPort"}
	records := []proto.Message{}
	for i := 0; i < 12; i++ {
		records = append(records, &types.HTTP{Timestamp: int64(time.Second), Host: "test", DstPort: 0, URL: string(rune('a' + i%3)), CommunityID: "1:test", RequestHeader: map[string]string{"z": "last", "a": "first"}})
	}
	var baseline string
	var ids []string
	for seed := int64(0); seed < 4; seed++ {
		dir := offlineTestDirectory(t)
		rand.New(rand.NewSource(seed)).Shuffle(len(records), func(i, j int) { records[i], records[j] = records[j], records[i] })
		offlineTestRecords(t, dir, "HTTP", seed%2 == 0, records)
		r := offlineTestEval(t, dir, pack)
		if r.CommittedAlerts != 6 {
			t.Fatal(r)
		}
		var eventIDs []string
		for _, a := range offlineTestAlerts(t, dir) {
			var m map[string]OfflineAlertMetadata
			json.Unmarshal([]byte(a.Notes), &m)
			eventIDs = append(eventIDs, m["netcapOffline"].EventID)
		}
		if seed == 0 {
			baseline = r.InputCanonicalDigest
			ids = eventIDs
		} else if baseline != r.InputCanonicalDigest || !reflect.DeepEqual(ids, eventIDs) {
			t.Fatal("semantic results depend on input order")
		}
	}
}

func TestOfflinePartialAndIsolation(t *testing.T) {
	dir := offlineTestDirectory(t)
	records := offlineTestTCP(2)
	records[0].(*types.TCP).SrcIP = ""
	offlineTestRecords(t, dir, "TCP", true, records)
	r := offlineTestEval(t, dir, offlineTestPack(2))
	if r.Status != "partial" || r.Rules[0].MissingGroups != 1 || r.CommittedAlerts != 0 {
		t.Fatalf("missing groups: %+v", r)
	}
	other := offlineTestDirectory(t)
	offlineTestRecords(t, other, "TCP", true, offlineTestTCP(1))
	if r := offlineTestEval(t, other, offlineTestPack(2)); r.CommittedAlerts != 0 {
		t.Fatal("cross-directory state leaked")
	}
	missing := offlineTestDirectory(t)
	if r := offlineTestEval(t, missing, offlineTestPack(2)); r.Status != "partial" || !r.Types[0].Missing {
		t.Fatal("missing telemetry not reported")
	}
}

func TestOfflineFailsClosed(t *testing.T) {
	cases := map[string]func(*testing.T, string){
		"timestamp": func(t *testing.T, d string) {
			r := offlineTestTCP(2)
			r[1].(*types.TCP).Timestamp = 0
			offlineTestRecords(t, d, "TCP", true, r)
		},
		"nan": func(t *testing.T, d string) {
			r := offlineTestTCP(2)
			r[1].(*types.TCP).PayloadEntropy = math.NaN()
			offlineTestRecords(t, d, "TCP", true, r)
		},
		"utf8": func(t *testing.T, d string) {
			r := offlineTestTCP(2)
			r[1].(*types.TCP).SrcIP = string([]byte{255})
			offlineTestRecords(t, d, "TCP", true, r)
		},
		"both": func(t *testing.T, d string) { offlineTestRecords(t, d, "TCP", false, offlineTestTCP(2)) },
		"checksum": func(t *testing.T, d string) {
			p := filepath.Join(d, "TCP.ncap.gz")
			b, _ := os.ReadFile(p)
			b[len(b)-8] ^= 0xff
			offlineTestWrite(t, p, b)
		},
		"truncated": func(t *testing.T, d string) {
			p := filepath.Join(d, "TCP.ncap.gz")
			b, _ := os.ReadFile(p)
			offlineTestWrite(t, p, b[:len(b)-4])
		},
		"header": func(t *testing.T, d string) {
			var b bytes.Buffer
			w := delimited.NewWriter(&b)
			w.PutProto(&types.Header{Type: types.Type_NC_UDP})
			os.Remove(filepath.Join(d, "TCP.ncap.gz"))
			offlineTestWrite(t, filepath.Join(d, "TCP.ncap"), b.Bytes())
		},
		"frame": func(t *testing.T, d string) {
			var b bytes.Buffer
			w := delimited.NewWriter(&b)
			w.PutProto(&types.Header{Type: types.Type_NC_TCP})
			var v [10]byte
			n := binary.PutUvarint(v[:], 4<<20+1)
			b.Write(v[:n])
			os.Remove(filepath.Join(d, "TCP.ncap.gz"))
			offlineTestWrite(t, filepath.Join(d, "TCP.ncap"), b.Bytes())
		},
		"ready-missing": func(t *testing.T, d string) { os.Remove(filepath.Join(d, OfflineReadyFile)) },
		"ready-mismatch": func(t *testing.T, d string) {
			offlineTestJSON(t, d, OfflineReadyFile, OfflineReadyMarker{1, "other-run"})
		},
		"active": func(t *testing.T, d string) {
			var m evidence.CaptureManifest
			b, _ := os.ReadFile(filepath.Join(d, "capture-manifest.json"))
			json.Unmarshal(b, &m)
			m.Status = "running"
			offlineTestJSON(t, d, "capture-manifest.json", m)
		},
		"bpf": func(t *testing.T, d string) {
			var m evidence.CaptureManifest
			b, _ := os.ReadFile(filepath.Join(d, "capture-manifest.json"))
			json.Unmarshal(b, &m)
			m.Config.BPF = "tcp"
			offlineTestJSON(t, d, "capture-manifest.json", m)
		},
		"scope": func(t *testing.T, d string) {
			var m evidence.CaptureManifest
			b, _ := os.ReadFile(filepath.Join(d, "capture-manifest.json"))
			json.Unmarshal(b, &m)
			m.CommunityScopes.Entries[0].Ambiguous = true
			offlineTestJSON(t, d, "capture-manifest.json", m)
		},
		"multi-scope": func(t *testing.T, d string) {
			var m evidence.CaptureManifest
			b, _ := os.ReadFile(filepath.Join(d, "capture-manifest.json"))
			json.Unmarshal(b, &m)
			m.CommunityScopes.Entries = append(m.CommunityScopes.Entries, evidence.CommunityScope{CommunityID: "1:second", Scope: evidence.FlowScope{Sensor: "other", InterfaceIndex: 1}})
			offlineTestJSON(t, d, "capture-manifest.json", m)
		},
		"symlink": func(t *testing.T, d string) {
			outside := filepath.Join(t.TempDir(), "TCP.ncap.gz")
			b, _ := os.ReadFile(filepath.Join(d, "TCP.ncap.gz"))
			offlineTestWrite(t, outside, b)
			os.Remove(filepath.Join(d, "TCP.ncap.gz"))
			if err := os.Symlink(outside, filepath.Join(d, "TCP.ncap.gz")); err != nil {
				t.Fatal(err)
			}
		},
	}
	for name, setup := range cases {
		t.Run(name, func(t *testing.T) {
			dir := offlineTestDirectory(t)
			offlineTestRecords(t, dir, "TCP", true, offlineTestTCP(2))
			setup(t, dir)
			if _, err := EvaluateOffline(context.Background(), OfflineRequest{Directory: dir, Pack: offlineTestPack(2)}); err == nil {
				t.Fatal("expected failure")
			}
			if _, err := os.Stat(filepath.Join(dir, "Alert.ncap.gz")); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("failed evaluation appended alerts")
			}
			if _, err := os.Stat(filepath.Join(dir, OfflineLeaseFile)); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("lease leaked")
			}
		})
	}
}

func TestOfflineCapsAndCancellation(t *testing.T) {
	caps := map[string]OfflineLimits{"records": {Records: 1}, "decoded": {DecodedBytes: 1}, "frame": {FrameBytes: 1}, "sort": {SortBytes: 1}, "state": {StateBytes: 1}, "groups": {GroupsPerRule: 1}, "pending": {PendingPerRule: 1}, "pending-job": {Pending: 1}, "alerts": {Alerts: 1}, "alert-bytes": {AlertBytes: 1}, "deadline": {Duration: 1}}
	for name, limits := range caps {
		t.Run(name, func(t *testing.T) {
			dir := offlineTestDirectory(t)
			records := offlineTestTCP(4)
			pack := offlineTestPack(2)
			if name == "groups" {
				pack = offlineTestPack(50)
				records[1].(*types.TCP).SrcIP = "other"
			}
			offlineTestRecords(t, dir, "TCP", true, records)
			if _, err := EvaluateOffline(context.Background(), OfflineRequest{Directory: dir, Pack: pack, Limits: limits}); err == nil {
				t.Fatal("cap not enforced")
			}
			if _, err := os.Stat(filepath.Join(dir, "Alert.ncap.gz")); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("cap failure published")
			}
		})
	}
	dir := offlineTestDirectory(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := EvaluateOffline(ctx, OfflineRequest{Directory: dir, Pack: offlineTestPack(2)}); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err := normalizeOfflineLimits(OfflineLimits{Records: -1}); err == nil {
		t.Fatal("negative cap admitted")
	}
	if _, err := normalizeOfflineLimits(OfflineLimits{Records: 100001}); err == nil {
		t.Fatal("hard cap raised")
	}
}

func TestOfflineLeaseSourceChangeAndPublicationFailure(t *testing.T) {
	dir := offlineTestDirectory(t)
	lease, err := AcquireOfflineLease(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := AcquireOfflineLease(dir); err == nil {
		t.Fatal("double lease")
	}
	if err := lease.Close(); err != nil {
		t.Fatal(err)
	}
	if err := lease.Close(); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	_, snapshots, err := offlineAdmission(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	markerInfo, err := os.Stat(filepath.Join(dir, OfflineReadyFile))
	if err != nil {
		t.Fatal(err)
	}
	offlineTestWrite(t, filepath.Join(dir, OfflineReadyFile), []byte(`{"version":1,"runId":"next-run"}`))
	if err := os.Chtimes(filepath.Join(dir, OfflineReadyFile), markerInfo.ModTime(), markerInfo.ModTime()); err != nil {
		t.Fatal(err)
	}
	if err := offlineRevalidate(context.Background(), root, snapshots); err == nil {
		t.Fatal("hash-only source change accepted")
	}
	offlineTestJSON(t, dir, OfflineReadyFile, OfflineReadyMarker{1, "test-run"})
	offlineTestRecords(t, dir, "TCP", true, offlineTestTCP(2))
	if err := os.Mkdir(filepath.Join(dir, "Alert.ncap.gz"), 0700); err != nil {
		t.Fatal(err)
	}
	r, err := EvaluateOffline(context.Background(), OfflineRequest{Directory: dir, Pack: offlineTestPack(2)})
	if err == nil || r == nil || r.Status != "publish-failed" || r.CommittedAlerts != 0 {
		t.Fatalf("publication failure: %+v %v", r, err)
	}
	listed, err := ListOfflineEvaluations(dir)
	if err != nil || len(listed) != 1 || listed[0].Status != "publish-failed" {
		t.Fatal(listed, err)
	}
	offlineTestWrite(t, filepath.Join(dir, "rule-evaluations", "bad.json"), []byte("{}"))
	if _, err := ListOfflineEvaluations(dir); err == nil {
		t.Fatal("malformed visible report hidden")
	}
}

func TestOfflineActualCaptureStatusesAndUnknownScope(t *testing.T) {
	for _, status := range []string{"done", "partial", "stopped"} {
		t.Run(status, func(t *testing.T) {
			dir := offlineTestDirectory(t)
			var m evidence.CaptureManifest
			b, _ := os.ReadFile(filepath.Join(dir, "capture-manifest.json"))
			json.Unmarshal(b, &m)
			m.Status = status
			offlineTestJSON(t, dir, "capture-manifest.json", m)
			offlineTestRecords(t, dir, "TCP", true, offlineTestTCP(2))
			r := offlineTestEval(t, dir, offlineTestPack(2))
			expected := "partial"
			if status == "done" {
				expected = "complete"
			}
			if r.Status != expected || r.CommittedAlerts != 1 {
				t.Fatal(r)
			}
		})
	}
	dir := offlineTestDirectory(t)
	records := offlineTestTCP(2)
	records[0].(*types.TCP).CommunityID = "1:unknown"
	offlineTestRecords(t, dir, "TCP", true, records)
	r := offlineTestEval(t, dir, offlineTestPack(2))
	if r.Status != "partial" || r.Types[0].UnknownScopes != 1 || r.CommittedAlerts != 0 {
		t.Fatal(r)
	}
}

type offlinePrefixContext struct {
	context.Context
	path string
}

func (c offlinePrefixContext) Err() error {
	info, err := os.Stat(c.path)
	if err == nil && info.Size() > 0 {
		return context.Canceled
	}
	return nil
}

func TestOfflineDurablePartialPrefixAndExistingHistory(t *testing.T) {
	dir := offlineTestDirectory(t)
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	digest := strings.Repeat("a", 64)
	report := &OfflineReport{Version: 1, ID: strings.Repeat("1", 32), RunID: "test-run", Status: "committing", StartedAt: time.Now().UTC().Format(time.RFC3339Nano), Limits: DefaultOfflineLimits(), PackDigest: digest, ConfigDigest: digest, InputCanonicalDigest: digest, Files: []OfflineFile{{Name: "capture-manifest.json", SHA256: digest}, {Name: OfflineReadyFile, SHA256: digest}}, Rules: []OfflineRuleStats{{ID: "test", Type: "TCP", Digest: digest}}, PlannedAlerts: 2}
	ctx := offlinePrefixContext{Context: context.Background(), path: filepath.Join(dir, "Alert.ncap.gz")}
	err = offlinePublish(ctx, dir, root, report, []*types.Alert{{Name: "first", Timestamp: 1}, {Name: "second", Timestamp: 2}}, false, time.Now())
	if !errors.Is(err, context.Canceled) || report.Status != "publish-failed" || report.CommittedAlerts != 1 {
		t.Fatalf("prefix: %+v %v", report, err)
	}
	if alerts := offlineTestAlerts(t, dir); len(alerts) != 1 || alerts[0].Name != "first" {
		t.Fatal("durable prefix missing", alerts)
	}
	listed, err := ListOfflineEvaluations(dir)
	if err != nil || len(listed) != 1 || listed[0].CommittedAlerts != 1 {
		t.Fatal(listed, err)
	}
	// An explicit subsequent evaluation appends without replacing the existing prefix.
	offlineTestRecords(t, dir, "TCP", true, offlineTestTCP(2))
	r := offlineTestEval(t, dir, offlineTestPack(2))
	if r.CommittedAlerts != 1 || len(offlineTestAlerts(t, dir)) != 2 {
		t.Fatal(r)
	}
}

func TestOfflineRejectsUnsafeExpressionsAndFieldAliases(t *testing.T) {
	for _, expression := range []string{`DurationSince(Timestamp)>0`, `HourOfDay(Timestamp)==1`, `IsApprovedWorkstation(SrcIP)`, `SYN == true; true`, `let a = 1; SYN`, `[1,2] | map(# + 1) == []`, `RequestHeader["host"] == "x"`, `keys(RequestHeader)[0] == "x"`, `Timestamp + 1 > 0`, `Timestamp in 1..100`, `SrcIP matches ".*"`, `Payload[0] == 1`, `GetSrcIP() == "x"`, `now() > date("2000-01-01")`} {
		t.Run(expression, func(t *testing.T) {
			p := offlineTestPack(2)
			p.Rules[0].Enabled = false
			p.Rules[0].Expression = expression
			if err := ValidateOfflinePack(p); err == nil || strings.Contains(err.Error(), "at least one enabled rule") {
				t.Fatal("unsafe expression admitted")
			}
		})
	}
	p := offlineTestPack(2)
	p.Rules[0].Threshold.GroupBy = []string{"src_ip"}
	if err := ValidateOfflinePack(p); err == nil || !strings.Contains(err.Error(), "exact Go") {
		t.Fatal("alias error unclear", err)
	}
	if _, err := LoadOfflinePack("offline-examples/grouped.yaml"); err != nil {
		t.Fatal(err)
	}
}

func TestOfflineLexicalRuleOrderAndBoundedHistory(t *testing.T) {
	dir := offlineTestDirectory(t)
	offlineTestRecords(t, dir, "TCP", true, offlineTestTCP(4))
	p := offlineTestPack(2)
	other := p.Rules[0]
	other.ID = "aaa"
	other.Name = "earlier"
	p.Rules = append(p.Rules, other)
	r := offlineTestEval(t, dir, p)
	if r.CommittedAlerts != 4 || r.Rules[0].ID != "aaa" {
		t.Fatal(r)
	}
	alerts := offlineTestAlerts(t, dir)
	if alerts[0].Name != "earlier" || alerts[1].Name != "earlier" || alerts[2].Name != "Grouped SYN" {
		t.Fatal("rule order changed")
	}
	if _, err := EvaluateOffline(context.Background(), OfflineRequest{Directory: dir, Pack: p, Limits: OfflineLimits{Rules: 1}}); err == nil {
		t.Fatal("rule cap ignored")
	}
	for i := 0; i < 99; i++ {
		name := fmt.Sprintf("%032x.json", i)
		copy := *r
		copy.ID = strings.TrimSuffix(name, ".json")
		offlineTestJSON(t, dir, filepath.Join("rule-evaluations", name), copy)
	}
	listed, err := ListOfflineEvaluations(dir)
	if err != nil || len(listed) != 100 {
		t.Fatal("bounded history", len(listed), err)
	}
	if _, err := EvaluateOffline(context.Background(), OfflineRequest{Directory: dir, Pack: p}); err == nil {
		t.Fatal("100-report admission cap ignored")
	}
	if len(offlineTestAlerts(t, dir)) != 4 {
		t.Fatal("history cap appended alerts")
	}
	copy := *r
	copy.ID = strings.Repeat("f", 32)
	offlineTestJSON(t, dir, filepath.Join("rule-evaluations", copy.ID+".json"), copy)
	if _, err := ListOfflineEvaluations(dir); err == nil {
		t.Fatal("oversized history admitted")
	}
}

func TestOfflineExpiredGroupReleasesCapacityAndKeyBounds(t *testing.T) {
	dir := offlineTestDirectory(t)
	records := offlineTestTCP(3)
	records[1].(*types.TCP).SrcIP = "second"
	records[1].(*types.TCP).Timestamp = int64(602 * time.Second)
	records[2].(*types.TCP).SrcIP = "second"
	records[2].(*types.TCP).Timestamp = int64(602*time.Second) + 1
	offlineTestRecords(t, dir, "TCP", true, records)
	r, err := EvaluateOffline(context.Background(), OfflineRequest{Directory: dir, Pack: offlineTestPack(2), Limits: OfflineLimits{GroupsPerRule: 1, Groups: 1}})
	if err != nil || r.CommittedAlerts != 1 {
		t.Fatal("expired group retained capacity", r, err)
	}
	other := offlineTestDirectory(t)
	bad := offlineTestTCP(2)
	bad[0].(*types.TCP).SrcIP = strings.Repeat("a", 1025)
	offlineTestRecords(t, other, "TCP", true, bad)
	if _, err := EvaluateOffline(context.Background(), OfflineRequest{Directory: other, Pack: offlineTestPack(2)}); err == nil {
		t.Fatal("oversized group admitted")
	}
	p := offlineTestPack(2)
	p.Rules[0].Threshold.Window = ""
	compiled, err := compileOfflinePack(p)
	if err != nil || compiled[0].window != int64(time.Minute) {
		t.Fatal("default window", err)
	}
}

func TestOfflineRejectsPublicationSymlinksAndCorruptHistory(t *testing.T) {
	for _, name := range []string{"rule-evaluations", "Alert.ncap.gz"} {
		t.Run(name, func(t *testing.T) {
			dir := offlineTestDirectory(t)
			offlineTestRecords(t, dir, "TCP", true, offlineTestTCP(2))
			outside := t.TempDir()
			if name == "Alert.ncap.gz" {
				outside = filepath.Join(outside, "history")
				offlineTestWrite(t, outside, []byte("unchanged"))
			}
			if err := os.Symlink(outside, filepath.Join(dir, name)); err != nil {
				t.Fatal(err)
			}
			if _, err := EvaluateOffline(context.Background(), OfflineRequest{Directory: dir, Pack: offlineTestPack(2)}); err == nil {
				t.Fatal("publication followed symlink")
			}
			if name == "Alert.ncap.gz" {
				b, _ := os.ReadFile(outside)
				if string(b) != "unchanged" {
					t.Fatal("escaped root")
				}
			}
		})
	}
	dir := offlineTestDirectory(t)
	offlineTestRecords(t, dir, "TCP", true, offlineTestTCP(2))
	offlineTestWrite(t, filepath.Join(dir, "Alert.ncap.gz"), []byte("corrupt"))
	r, err := EvaluateOffline(context.Background(), OfflineRequest{Directory: dir, Pack: offlineTestPack(2)})
	if err == nil || r == nil || r.Status != "publish-failed" || r.CommittedAlerts != 0 {
		t.Fatal(r, err)
	}
}

func TestOfflineJSONPreservesNanosecondsAndIntegerGroups(t *testing.T) {
	dir := offlineTestDirectory(t)
	const first int64 = 1700000000000000001
	records := offlineTestTCP(4)
	for i, r := range records {
		r.(*types.TCP).Timestamp = first + int64(i/2)
	}
	p := offlineTestPack(2)
	p.Rules[0].Threshold.GroupBy = []string{"Timestamp", "DstPort", "SeqNum", "SrcIP"}
	offlineTestRecords(t, dir, "TCP", true, records)
	report := offlineTestEval(t, dir, p)
	alerts := offlineTestAlerts(t, dir)
	if len(alerts) != 2 {
		t.Fatalf("adjacent nanosecond groups merged: %d alerts", len(alerts))
	}
	for i, a := range alerts {
		var envelope map[string]any
		if err := json.Unmarshal([]byte(a.Notes), &envelope); err != nil {
			t.Fatal(err)
		}
		m := envelope["netcapOffline"].(map[string]any)
		want := strconv.FormatInt(first+int64(i), 10)
		if m["first"] != want || m["last"] != want || m["windowNs"] != "600000000000" {
			t.Fatalf("unsafe nanoseconds: %s", a.Notes)
		}
		g := m["group"].(map[string]any)
		for name, expected := range map[string]map[string]any{
			"Timestamp": {"type": "int64", "value": want},
			"DstPort":   {"type": "int32", "value": "80"},
			"SeqNum":    {"type": "uint32", "value": "0"},
		} {
			if !reflect.DeepEqual(g[name], expected) {
				t.Fatalf("group %s: %#v", name, g[name])
			}
		}
		if g["SrcIP"] != "192.0.2.1" {
			t.Fatal(g)
		}
		ref := m["contributors"].([]any)[0].(map[string]any)
		if ref["timestamp"] != want || ref["ordinal"] != strconv.Itoa(i*2) {
			t.Fatal(ref)
		}
	}
	b, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	var wire map[string]any
	if err := json.Unmarshal(b, &wire); err != nil {
		t.Fatal(err)
	}
	if wire["committedAlerts"] != "2" || wire["plannedAlerts"] != "2" || wire["elapsed"] != strconv.FormatInt(int64(report.Elapsed), 10) {
		t.Fatal(string(b))
	}
}

func TestOfflineEventIdentityConfigAndProvenance(t *testing.T) {
	var baselineDigest, baselineID, baselineConfig, baselinePolicy string
	for i := 0; i < 3; i++ {
		dir := offlineTestDirectory(t)
		var m evidence.CaptureManifest
		b, err := os.ReadFile(filepath.Join(dir, "capture-manifest.json"))
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(b, &m); err != nil {
			t.Fatal(err)
		}
		m.RunID = fmt.Sprintf("run-%d", i)
		m.Config.Workers = i + 1
		m.Config.Source = filepath.Join(dir, "source.pcap")
		if i == 2 {
			m.Config.SnapLen = 128
		}
		offlineTestJSON(t, dir, "capture-manifest.json", m)
		offlineTestJSON(t, dir, OfflineReadyFile, OfflineReadyMarker{1, m.RunID})
		records := offlineTestTCP(2)
		if i == 1 {
			records[0], records[1] = records[1], records[0]
		}
		offlineTestRecords(t, dir, "TCP", i%2 == 0, records)
		r := offlineTestEval(t, dir, offlineTestPack(2))
		var notes map[string]OfflineAlertMetadata
		if err := json.Unmarshal([]byte(offlineTestAlerts(t, dir)[0].Notes), &notes); err != nil {
			t.Fatal(err)
		}
		id := notes["netcapOffline"].EventID
		if notes["netcapOffline"].ObservationPolicyDigest != r.ObservationPolicyDigest {
			t.Fatal("missing observation policy provenance")
		}
		if i == 0 {
			baselineDigest, baselineID = r.InputCanonicalDigest, id
			baselineConfig, baselinePolicy = r.ConfigDigest, r.ObservationPolicyDigest
		} else if r.InputCanonicalDigest != baselineDigest || (id == baselineID) != (i == 1) {
			t.Fatalf("identity does not distinguish config from provenance: run %d", i)
		}
		if i > 0 && (r.ConfigDigest == baselineConfig || (r.ObservationPolicyDigest == baselinePolicy) != (i == 1)) {
			t.Fatalf("policy/full configuration separation failed: run %d", i)
		}
	}
}

func TestOfflineEventIdentityPackOrder(t *testing.T) {
	var baselineDigest string
	var baselineIDs []string
	for i := 0; i < 2; i++ {
		dir := offlineTestDirectory(t)
		offlineTestRecords(t, dir, "TCP", true, offlineTestTCP(4))
		pack := offlineTestPack(2)
		other := pack.Rules[0]
		other.ID = "another-rule"
		other.Name = "Another rule"
		pack.Rules = append(pack.Rules, other)
		if i == 1 {
			pack.Rules[0], pack.Rules[1] = pack.Rules[1], pack.Rules[0]
		}
		r := offlineTestEval(t, dir, pack)
		var ids []string
		for _, alert := range offlineTestAlerts(t, dir) {
			var notes map[string]OfflineAlertMetadata
			if err := json.Unmarshal([]byte(alert.Notes), &notes); err != nil {
				t.Fatal(err)
			}
			ids = append(ids, notes["netcapOffline"].EventID)
		}
		if i == 0 {
			baselineDigest = r.PackDigest
			baselineIDs = ids
		} else if r.PackDigest != baselineDigest || !reflect.DeepEqual(ids, baselineIDs) {
			t.Fatal("pack order changed event identity")
		}
	}
}

func TestOfflineWholeInputBudgets(t *testing.T) {
	for _, cap := range []string{"records", "decoded", "exact"} {
		t.Run(cap, func(t *testing.T) {
			dir := offlineTestDirectory(t)
			offlineTestRecords(t, dir, "TCP", false, offlineTestTCP(1))
			offlineTestRecords(t, dir, "HTTP", false, []proto.Message{&types.HTTP{Timestamp: 1, Host: "test", CommunityID: "1:test"}})
			p := offlineTestPack(2)
			p.Rules = append(p.Rules, OfflineRule{ID: "http", Name: "HTTP", Type: "HTTP", Expression: `Host == "test"`, Enabled: true, Severity: "low", Threshold: OfflineThreshold{Count: 2, Window: "1s", GroupBy: []string{"Host"}}})
			var size int64
			for _, name := range []string{"TCP.ncap", "HTTP.ncap"} {
				info, err := os.Stat(filepath.Join(dir, name))
				if err != nil {
					t.Fatal(err)
				}
				size += info.Size()
			}
			limits := OfflineLimits{Records: 2, DecodedBytes: size}
			if cap == "records" {
				limits.Records--
			} else if cap == "decoded" {
				limits.DecodedBytes--
			}
			r, err := EvaluateOffline(context.Background(), OfflineRequest{Directory: dir, Pack: p, Limits: limits})
			if cap == "exact" {
				if err != nil || r.Status != "complete" || len(r.Types) != 2 {
					t.Fatal(r, err)
				}
			} else if err == nil {
				t.Fatal("budget was reset between types")
			}
			if len(offlineTestAlerts(t, dir)) != 0 {
				t.Fatal("whole-input failure published alerts")
			}
		})
	}
}

func TestOfflineDisabledPackAndMissingCommunityID(t *testing.T) {
	dir := offlineTestDirectory(t)
	p := offlineTestPack(2)
	p.Rules[0].Enabled = false
	if _, err := EvaluateOffline(context.Background(), OfflineRequest{Directory: dir, Pack: p}); err == nil || !strings.Contains(err.Error(), "enabled") {
		t.Fatal("empty enabled set admitted", err)
	}
	records := offlineTestTCP(3)
	records[1].(*types.TCP).CommunityID = ""
	offlineTestRecords(t, dir, "TCP", true, records)
	r := offlineTestEval(t, dir, offlineTestPack(2))
	if r.Status != "partial" || r.Types[0].UnknownScopes != 1 || r.Rules[0].Matches != 2 || r.CommittedAlerts != 1 {
		t.Fatalf("unqualified retained row contaminated results: %+v", r)
	}
}

func TestOfflineSortCancellationDuringWork(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	values := make([]int, 32768)
	for i := range values {
		values[i] = len(values) - i
	}
	comparisons := 0
	err := offlineSortValues(ctx, values, func(a, b int) bool {
		comparisons++
		if comparisons == 100 {
			cancel()
		}
		return a < b
	})
	if !errors.Is(err, context.Canceled) || comparisons >= len(values) {
		t.Fatalf("sort ignored cancellation: %d comparisons, %v", comparisons, err)
	}
}

func TestOfflineScopeQualifiers(t *testing.T) {
	for _, qualifier := range []string{"empty-vlans", "sensor", "interface", "vlan"} {
		t.Run(qualifier, func(t *testing.T) {
			dir := offlineTestDirectory(t)
			var m evidence.CaptureManifest
			b, err := os.ReadFile(filepath.Join(dir, "capture-manifest.json"))
			if err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(b, &m); err != nil {
				t.Fatal(err)
			}
			e := m.CommunityScopes.Entries[0]
			e.CommunityID = "1:second"
			switch qualifier {
			case "empty-vlans":
				e.Scope.VLANs = nil
			case "sensor":
				e.Scope.Sensor = "other"
			case "interface":
				e.Scope.InterfaceIndex++
			case "vlan":
				e.Scope.VLANs = []uint16{12}
			}
			m.CommunityScopes.Entries = append(m.CommunityScopes.Entries, e)
			offlineTestJSON(t, dir, "capture-manifest.json", m)
			offlineTestRecords(t, dir, "TCP", true, offlineTestTCP(2))
			r, err := EvaluateOffline(context.Background(), OfflineRequest{Directory: dir, Pack: offlineTestPack(2)})
			if qualifier == "empty-vlans" {
				if err != nil || r.CommittedAlerts != 1 {
					t.Fatal("equivalent empty scope representations differ", r, err)
				}
			} else if err == nil || len(offlineTestAlerts(t, dir)) != 0 {
				t.Fatal("cross-qualified scope admitted", r, err)
			}
		})
	}
}

func TestOfflineStaleLeaseAndActiveWriter(t *testing.T) {
	dir := offlineTestDirectory(t)
	offlineTestRecords(t, dir, "TCP", true, offlineTestTCP(2))
	lock := filepath.Join(dir, OfflineLeaseFile)
	offlineTestWrite(t, lock, []byte("operator-owned stale lock"))
	if _, err := EvaluateOffline(context.Background(), OfflineRequest{Directory: dir, Pack: offlineTestPack(2)}); err == nil {
		t.Fatal("existing lease replaced")
	}
	if b, err := os.ReadFile(lock); err != nil || string(b) != "operator-owned stale lock" {
		t.Fatal("existing lease modified", string(b), err)
	}
	if err := os.Remove(lock); err != nil {
		t.Fatal(err)
	}
	w, err := NewFileAlertWriter(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	r, err := EvaluateOffline(context.Background(), OfflineRequest{Directory: dir, Pack: offlineTestPack(2)})
	if err == nil || r == nil || r.Status != "publish-failed" || r.CommittedAlerts != 0 || !strings.Contains(err.Error(), "active writer") {
		t.Fatal("active writer conflict lost", r, err)
	}
	listed, err := ListOfflineEvaluations(dir)
	if err != nil || len(listed) != 1 || listed[0].Status != "publish-failed" || listed[0].Error == "" {
		t.Fatal("writer failure not persisted", listed, err)
	}
	if _, err := os.Stat(lock); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("failed publication leaked its lease", err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if next := offlineTestEval(t, dir, offlineTestPack(2)); next.CommittedAlerts != 1 {
		t.Fatal("writer conflict left stale state", next)
	}
}
