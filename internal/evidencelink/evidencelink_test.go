package evidencelink

import (
	"testing"
	"time"

	"github.com/dreadl0ck/netcap"
	"github.com/dreadl0ck/netcap/defaults"
	"github.com/dreadl0ck/netcap/internal/netio"
	"github.com/dreadl0ck/netcap/types"
	"github.com/gogo/protobuf/proto"
)

const (
	cidA = "1:aaaaaaaaaaaaaaaaaaaaaaaaaaa="
	cidB = "1:bbbbbbbbbbbbbbbbbbbbbbbbbbb="
	t0   = int64(1_800_000_000_000_000_000)
	sec  = int64(time.Second)
)

func writeFile(t *testing.T, dir, name string, typ types.Type, records ...types.AuditRecord) {
	t.Helper()
	w := netio.NewAuditRecordWriter(&netio.WriterConfig{
		Proto: true, Name: name, Buffer: true, Compress: true, Out: dir,
		MemBufferSize: defaults.BufferSize, Source: "evidencelink test", Version: netcap.Version,
		StartTime: time.Unix(0, t0), CompressionBlockSize: defaults.CompressionBlockSize,
	})
	if err := w.WriteHeader(typ); err != nil {
		t.Fatal(err)
	}
	for _, r := range records {
		if err := w.Write(r.(proto.Message)); err != nil {
			t.Fatal(err)
		}
	}
	w.Close(int64(len(records)))
}

func fixture(t *testing.T) string {
	dir := t.TempDir()
	writeFile(t, dir, "DNS", types.Type_NC_DNS,
		&types.DNS{Timestamp: t0, QR: false, SrcIP: "10.0.0.5", DstIP: "10.0.0.53", CommunityID: "1:dnsaaaaaaaaaaaaaaaaaaaaaaaa=", Questions: []*types.DNSQuestion{{Name: "example.test", Type: 1}}},
		&types.DNS{Timestamp: t0 + sec, QR: true, SrcIP: "10.0.0.53", DstIP: "10.0.0.5", CommunityID: "1:dnsaaaaaaaaaaaaaaaaaaaaaaaa=", TransactionStatus: "answered",
			Questions: []*types.DNSQuestion{{Name: "example.test", Type: 1}}, Answers: []*types.DNSResourceRecord{{Type: 1, IP: "192.0.2.80"}}},
	)
	writeFile(t, dir, "Connection", types.Type_NC_Connection,
		// Two snapshots of one observation, then a reused tuple.
		&types.Connection{TimestampFirst: t0 + 2*sec, TimestampLast: t0 + 3*sec, SrcIP: "10.0.0.5", SrcPort: "40000", DstIP: "192.0.2.80", DstPort: "80", CommunityID: cidA, ObservationID: "obs1", SnapshotSequence: 1},
		&types.Connection{TimestampFirst: t0 + 2*sec, TimestampLast: t0 + 5*sec, SrcIP: "10.0.0.5", SrcPort: "40000", DstIP: "192.0.2.80", DstPort: "80", CommunityID: cidA, ObservationID: "obs1", SnapshotSequence: 2},
		&types.Connection{TimestampFirst: t0 + 100*sec, TimestampLast: t0 + 101*sec, SrcIP: "10.0.0.5", SrcPort: "40000", DstIP: "192.0.2.80", DstPort: "80", CommunityID: cidA, ObservationID: "obs2", SnapshotSequence: 1},
		&types.Connection{TimestampFirst: t0 + 7200*sec, TimestampLast: t0 + 7201*sec, SrcIP: "10.0.0.5", SrcPort: "40001", DstIP: "192.0.2.80", DstPort: "80", CommunityID: cidB, ObservationID: "obs3", SnapshotSequence: 1},
	)
	writeFile(t, dir, "HTTP", types.Type_NC_HTTP,
		&types.HTTP{Timestamp: t0 + 2*sec + 1, Method: "GET", Host: "example.test", URL: "/a", StatusCode: 200, CommunityID: cidA},
		&types.HTTP{Timestamp: t0 + 100*sec, Method: "GET", Host: "example.test", URL: "/reused", CommunityID: cidA},
		&types.HTTP{Timestamp: t0 + 2*sec, Method: "GET", URL: "/fallback", CommunityID: "0f00"},
	)
	writeFile(t, dir, "Alert", types.Type_NC_Alert,
		&types.Alert{Timestamp: t0 + 2*sec + 1, RuleName: "rule", Severity: "high", RecordType: "NC_HTTP", MatchedRecord: `{"CommunityID":"` + cidA + `"}`},
	)
	return dir
}

func kinds(result *Result) []string {
	var out []string
	for _, link := range result.Links {
		out = append(out, link.Kind+":"+link.Record.Type+":"+link.Record.Summary[0].Value)
	}
	return out
}

func TestRelatedJoinsConnectionDNSAndAlerts(t *testing.T) {
	idx, err := Build(fixture(t), DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	result, err := idx.Related("HTTP", 0)
	if err != nil {
		t.Fatal(err)
	}
	if result.Session == nil || result.Session.ObservationID != "obs1" || result.Session.Last != t0+5*sec {
		t.Fatalf("session = %+v", result.Session)
	}
	want := []string{"dns-resolution:DNS:example.test", "same-connection:Connection:10.0.0.5", "alert:Alert:rule"}
	if got := kinds(result); len(got) != len(want) {
		t.Fatalf("links = %v", got)
	} else {
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("links = %v, want %v", got, want)
			}
		}
	}
	// The DNS link is the response that carried the answer, before the connection.
	if result.Links[0].Basis != BasisAnswerBefore || result.Links[0].Record.Timestamp != t0+sec {
		t.Fatalf("dns link = %+v", result.Links[0])
	}
}

func TestTupleReuseAndSnapshotsStaySeparate(t *testing.T) {
	idx, _ := Build(fixture(t), DefaultConfig())
	result, err := idx.Related("HTTP", 1)
	if err != nil {
		t.Fatal(err)
	}
	if result.Session == nil || result.Session.ObservationID != "obs2" {
		t.Fatalf("session = %+v", result.Session)
	}
	for _, link := range result.Links {
		if link.Kind != KindDNSResolution && link.Record.Timestamp < t0+100*sec {
			t.Fatalf("earlier observation leaked: %+v", link)
		}
	}
	// Earlier snapshot resolves to the latest snapshot of the same observation.
	first, _ := idx.Related("Connection", 0)
	if first.Session.ObservationID != "obs1" || first.Session.Ordinal != 1 {
		t.Fatalf("snapshot session = %+v", first.Session)
	}
}

func TestDNSAnswerLinksLaterConnectionsWithinWindow(t *testing.T) {
	idx, _ := Build(fixture(t), DefaultConfig())
	result, err := idx.Related("DNS", 1)
	if err != nil {
		t.Fatal(err)
	}
	var resolved []string
	for _, link := range result.Links {
		if link.Kind == KindResolvedConnection {
			resolved = append(resolved, link.Record.CommunityID)
		}
	}
	// obs1 and obs2 start within one hour of the answer; obs3 does not.
	if len(resolved) != 2 || resolved[0] != cidA || resolved[1] != cidA {
		t.Fatalf("resolved = %v", resolved)
	}
}

func TestFallbackIdentifiersAndLimits(t *testing.T) {
	dir := fixture(t)
	idx, _ := Build(dir, DefaultConfig())
	if _, err := idx.Related("HTTP", 2); err != ErrNotFound {
		t.Fatalf("non-Community-ID record indexed: %v", err)
	}
	config := DefaultConfig()
	config.MaxLinks = 1
	idx, _ = Build(dir, config)
	result, _ := idx.Related("HTTP", 0)
	if len(result.Links) != 1 || !result.Truncated {
		t.Fatalf("link cap not applied: %+v", result)
	}
	config = DefaultConfig()
	config.MaxRecords = 2
	idx, _ = Build(dir, config)
	if idx.indexed != 2 || !idx.full {
		t.Fatalf("record cap not applied: %d", idx.indexed)
	}
	for _, bad := range []Config{{WindowNS: 0, MaxRecords: 1, MaxLinks: 1}, {WindowNS: 1, MaxRecords: 0, MaxLinks: 1}, {WindowNS: 1, MaxRecords: 1, MaxLinks: 0}} {
		if bad.Validate() == nil {
			t.Fatalf("accepted %+v", bad)
		}
	}
}

func TestAmbiguousAndExtremeTimesDoNotInventLinks(t *testing.T) {
	dir := fixture(t)
	writeFile(t, dir, "HTTP", types.Type_NC_HTTP,
		&types.HTTP{Timestamp: t0 + 2*sec + 1, CommunityID: cidA},
		&types.HTTP{Timestamp: t0 + 2*sec + 1, CommunityID: cidA},
		&types.HTTP{Timestamp: t0 + 50*sec, CommunityID: cidA},
	)
	idx, err := Build(dir, DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := idx.Resolve(Selector{Type: "HTTP", CommunityID: cidA, Time: t0 + 2*sec + 1, HasTime: true}); err == nil {
		t.Fatal("duplicate timestamp selected an arbitrary record")
	}
	gap, err := idx.Related("HTTP", 2)
	if err != nil {
		t.Fatal(err)
	}
	if gap.Session != nil || len(gap.Links) != 0 {
		t.Fatalf("linked across tuple reuse: %+v", gap)
	}
	if within(-1<<63, 1<<63-1, 1) || !within(-1<<63, -1<<63+1, 1) {
		t.Fatal("timestamp distance overflowed")
	}
	if _, err := Build(dir+"/missing", DefaultConfig()); err == nil {
		t.Fatal("missing directory accepted")
	}
}

func TestContentBoundReferencesRejectReplacedAuditFiles(t *testing.T) {
	dir := fixture(t)
	index, err := Build(dir, DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	before, err := index.Related("HTTP", 0)
	if err != nil {
		t.Fatal(err)
	}
	typ, ordinal, err := index.Resolve(Selector{ID: before.Target.ID})
	if err != nil || typ != "HTTP" || ordinal != 0 {
		t.Fatalf("reference failed: %s %d %v", typ, ordinal, err)
	}
	if len(before.Target.FileSHA256) != 64 || len(before.Target.ID) != 64 {
		t.Fatal("missing content identity")
	}
	writeFile(t, dir, "HTTP", types.Type_NC_HTTP, &types.HTTP{Timestamp: t0 + 2*sec + 1, CommunityID: cidA, URL: "/replacement"})
	after, err := Build(dir, DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := after.Resolve(Selector{ID: before.Target.ID}); err != ErrNotFound {
		t.Fatalf("old reference rebound: %v", err)
	}
}
