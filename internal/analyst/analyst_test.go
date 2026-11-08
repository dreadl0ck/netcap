package analyst

import (
	"compress/gzip"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/dreadl0ck/netcap/internal/delimited"
	"github.com/dreadl0ck/netcap/internal/evidence"
	"github.com/dreadl0ck/netcap/internal/netio"
	"github.com/dreadl0ck/netcap/types"
	"github.com/gogo/protobuf/proto"
)

func fixture(t *testing.T, id string) (Source, []Reference) {
	t.Helper()
	dir := t.TempDir()
	m := evidence.CaptureManifest{Version: 1, RunID: id, InputSHA256: Digest([]byte("source")), Status: "done"}
	data, _ := json.Marshal(m)
	write(t, dir, "capture-manifest.json", data)
	write(t, dir, evidence.AuditReadyFile, []byte(`{"version":1,"runId":"`+id+`"}`))
	record := &types.Connection{TimestampFirst: 1700000000000000001, TimestampLast: 1700000000000000002, SrcIP: "192.0.2.1", DstIP: "192.0.2.2", TransportProto: "TCP"}
	audit(t, dir, "Connection", types.Type_NC_Connection, record, record)
	b, err := Bind(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	source := Source{ID: id, Binding: b, Directory: dir}
	refs := []Reference{}
	if err = Walk(context.Background(), dir, b, "Connection", func(ref Reference, _ proto.Message) error { refs = append(refs, ref); return nil }); err != nil {
		t.Fatal(err)
	}
	return source, refs
}
func write(t *testing.T, dir, name string, b []byte) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), b, 0600); err != nil {
		t.Fatal(err)
	}
}
func audit(t *testing.T, dir, name string, typ types.Type, records ...proto.Message) {
	t.Helper()
	f, err := os.Create(filepath.Join(dir, name+".ncap.gz"))
	if err != nil {
		t.Fatal(err)
	}
	z := gzip.NewWriter(f)
	w := delimited.NewWriter(z)
	if err = w.PutProto(&types.Header{Type: typ}); err != nil {
		t.Fatal(err)
	}
	for _, record := range records {
		if err = w.PutProto(record); err != nil {
			t.Fatal(err)
		}
	}
	if err = z.Close(); err != nil {
		t.Fatal(err)
	}
	if err = f.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestOccurrenceIdentityRejectsRebindingAndRetainsDuplicates(t *testing.T) {
	source, refs := fixture(t, "one")
	if len(refs) != 2 || refs[0].RecordSHA256 != refs[1].RecordSHA256 || refs[0].Ordinal == refs[1].Ordinal {
		t.Fatal("duplicate occurrences collapsed")
	}
	data, err := Resolve(context.Background(), source.Directory, refs[0])
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"TimestampFirst":"1700000000000000001"`) {
		t.Fatalf("lost timestamp precision: %s", data)
	}
	for _, mutate := range []func(*Reference){func(r *Reference) { r.Ordinal = "1"; r.RecordSHA256 = Digest([]byte("different")) }, func(r *Reference) { r.FileSHA256 = Digest([]byte("different")) }, func(r *Reference) { r.Binding.RunID = "other" }, func(r *Reference) { r.Binding.SourceSHA256 = Digest([]byte("other")) }, func(r *Reference) { r.Binding.ManifestSHA256 = Digest([]byte("other")) }, func(r *Reference) { r.File = "../outside" }} {
		bad := refs[0]
		mutate(&bad)
		if _, err := Resolve(context.Background(), source.Directory, bad); err == nil {
			t.Fatalf("rebound %+v", bad)
		}
	}
	audit(t, source.Directory, "Connection", types.Type_NC_Connection, &types.Connection{TimestampFirst: 1700000000000000001, TimestampLast: 1700000000000000002, SrcIP: "198.51.100.1"})
	if _, err := Resolve(context.Background(), source.Directory, refs[0]); !errors.Is(err, ErrStale) {
		t.Fatalf("changed file not stale: %v", err)
	}
}

func TestCatalogueExplicitCoverageAndNovelty(t *testing.T) {
	target, _ := fixture(t, "target")
	baseline, _ := fixture(t, "baseline")
	q := Query{"endpoint", "192.0.2.1", []string{"Connection"}}
	result, err := Search(context.Background(), []Source{target, baseline}, q)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Occurrences) != 4 || len(result.Coverage) != 2 || result.Novelty != "observed-in-included-baseline" {
		t.Fatalf("bad catalogue %+v", result)
	}
	audit(t, baseline.Directory, "Connection", types.Type_NC_Connection, &types.Connection{SrcIP: "198.51.100.1", DstIP: "198.51.100.2"})
	result, err = Search(context.Background(), []Source{target, baseline}, q)
	if err != nil || result.Novelty != "new-within-included-baseline" {
		t.Fatalf("novelty %+v %v", result, err)
	}
	if err = os.Remove(filepath.Join(baseline.Directory, "Connection.ncap.gz")); err != nil {
		t.Fatal(err)
	}
	result, err = Search(context.Background(), []Source{target, baseline}, q)
	if err != nil || result.Novelty != "unknown" || result.Coverage[1].State != "absent" {
		t.Fatalf("missing became novel: %+v %v", result, err)
	}
	for _, query := range []Query{{"sha256", "not-hash", []string{"File"}}, {"endpoint", "192.0.2", []string{"Connection"}}, {"text", "password", []string{"Secret"}}, {"domain", "example.test", []string{"Connection"}}, {"text", "TCP", []string{"Connection", "Connection"}}} {
		if _, err := Search(context.Background(), []Source{target}, query); err == nil {
			t.Fatalf("unsupported query accepted %+v", query)
		}
	}
	if _, err := Search(context.Background(), []Source{target, target}, q); err == nil {
		t.Fatal("duplicate inclusion accepted")
	}
}

func TestIndicatorFieldSemantics(t *testing.T) {
	tests := []struct {
		q      Query
		typ    string
		record proto.Message
		want   int
	}{
		{Query{"domain", "EXAMPLE.TEST.", []string{"DNS"}}, "DNS", &types.DNS{Questions: []*types.DNSQuestion{{Name: "example.test"}}, Answers: []*types.DNSResourceRecord{{Name: "example.test"}}}, 2},
		{Query{"sha256", strings.Repeat("a", 64), []string{"File"}}, "File", &types.File{Hashes: &types.FileHashes{SHA256: strings.Repeat("A", 64)}}, 1},
		{Query{"text", "server", []string{"Software"}}, "Software", &types.Software{Product: "server", Vendor: "other"}, 1},
		{Query{"endpoint", "192.0.2.1", []string{"Connection"}}, "Connection", &types.Connection{SrcIP: "192.0.2.10", DstIP: "192.0.2.2"}, 0},
	}
	for _, tc := range tests {
		if got := Match(tc.q, tc.record, tc.typ); len(got) != tc.want {
			t.Fatalf("%s got %+v", tc.typ, got)
		}
	}
}

func TestWorkspaceAtomicCASAndReview(t *testing.T) {
	source, refs := fixture(t, "workspace")
	ctx := context.Background()
	q := Query{"text", "TCP", []string{"Connection"}}
	doc := Document{Kind: "query", Title: "Find TCP", Binding: source.Binding, Query: &q, References: refs[:1], Review: "draft", IncludedSources: []SourceSelection{{SessionID: source.ID, Binding: source.Binding}}}
	snapshot, err := Search(ctx, []Source{source}, q)
	if err != nil {
		t.Fatal(err)
	}
	doc.CatalogueSnapshotSHA256 = snapshot.SnapshotSHA256
	saved, err := SaveDocument(ctx, source.Directory, source.Binding, doc, 0)
	if err != nil {
		t.Fatal(err)
	}
	edited := saved
	edited.Body = "new content"
	edited.Review = "reviewed"
	edited.Reviewer = "analyst"
	if _, err = SaveDocument(ctx, source.Directory, source.Binding, edited, 1); err == nil {
		t.Fatal("reviewed changed content")
	}
	var wg sync.WaitGroup
	success := 0
	var mu sync.Mutex
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			next := saved
			next.Body = "saved"
			_, e := SaveDocument(ctx, source.Directory, source.Binding, next, 1)
			if e == nil {
				mu.Lock()
				success++
				mu.Unlock()
			} else if !errors.Is(e, ErrStale) {
				t.Errorf("unexpected CAS %v", e)
			}
		}()
	}
	wg.Wait()
	if success != 1 {
		t.Fatalf("CAS successes %d", success)
	}
	w, err := LoadWorkspace(ctx, source.Directory, source.Binding)
	if err != nil {
		t.Fatal(err)
	}
	review := w.Documents[0]
	review.Review = "reviewed"
	review.Reviewer = "human analyst"
	reviewed, err := SaveDocument(ctx, source.Directory, source.Binding, review, 2)
	if err != nil || reviewed.Review != "reviewed" || reviewed.Revision != 3 {
		t.Fatalf("review %+v %v", reviewed, err)
	}
	ctx, cancel := context.WithCancel(ctx)
	cancel()
	if _, err = SaveDocument(ctx, source.Directory, source.Binding, reviewed, 3); err == nil {
		t.Fatal("canceled save succeeded")
	}
	recovered, err := LoadWorkspace(context.Background(), source.Directory, source.Binding)
	if err != nil || recovered.Documents[0].Revision != 3 {
		t.Fatal("canceled save corrupted workspace")
	}
}

func TestSafeLogReviewRejectsStaleAndNeverPersistsRawSecrets(t *testing.T) {
	source, _ := fixture(t, "logs")
	secret := "password=RAW_SECRET_SENTINEL"
	write(t, source.Directory, "capture.log", []byte("error "+secret+"\ncompleted\n"))
	preview, err := PreviewLog(context.Background(), source.Directory, source.Binding, "capture.log", 1, 2)
	if err != nil {
		t.Fatal(err)
	}
	bytes, _ := json.Marshal(preview)
	if strings.Contains(string(bytes), secret) {
		t.Fatal("raw log leaked")
	}
	if err = ApproveLog(context.Background(), source.Directory, preview); err != nil {
		t.Fatal(err)
	}
	review, err := ReviewedLog(context.Background(), source.Directory, source.Binding)
	if err != nil || review.State != "reviewed" {
		t.Fatal(err)
	}
	persisted, err := os.ReadFile(filepath.Join(source.Directory, ReviewedLogFile))
	if err != nil || strings.Contains(string(persisted), "RAW_SECRET_SENTINEL") {
		t.Fatal("persisted raw secret")
	}
	write(t, source.Directory, "capture.log", []byte("warning new bytes\ncompleted\n"))
	if _, err = ReviewedLog(context.Background(), source.Directory, source.Binding); !errors.Is(err, ErrStale) {
		t.Fatalf("stale attachment accepted %v", err)
	}
}

func TestConfinementCorruptionAndCancellation(t *testing.T) {
	source, refs := fixture(t, "bounds")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Resolve(ctx, source.Directory, refs[0]); err == nil {
		t.Fatal("cancellation ignored")
	}
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(outside, []byte("OUTSIDE"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(source.Directory, "Connection.ncap.gz")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(source.Directory, "Connection.ncap.gz")); err != nil {
		t.Fatal(err)
	}
	if err := Walk(context.Background(), source.Directory, source.Binding, "Connection", func(Reference, proto.Message) error { t.Fatal("escaped callback"); return nil }); err == nil {
		t.Fatal("symlink accepted")
	}
	if err := os.Remove(filepath.Join(source.Directory, "Connection.ncap.gz")); err != nil {
		t.Fatal(err)
	}
	var prefix [10]byte
	n := binary.PutUvarint(prefix[:], 5<<20)
	write(t, source.Directory, "Connection.ncap", prefix[:n])
	if err := Walk(context.Background(), source.Directory, source.Binding, "Connection", func(Reference, proto.Message) error { return nil }); err == nil {
		t.Fatal("oversized frame accepted")
	}
	if err := AtomicJSON(context.Background(), source.Directory, "../outside", []byte("bad"), nil); err == nil {
		t.Fatal("unsafe destination accepted")
	}
}

func TestCatalogueFieldContractMatchesSupportedSchemas(t *testing.T) {
	for name, kinds := range catalogueFields {
		msg := netio.InitRecord(types.Type(types.Type_value["NC_"+name]))
		if msg == nil {
			t.Fatalf("missing supported type %s", name)
		}
		for _, fields := range kinds {
			for _, path := range fields {
				typ := reflect.TypeOf(msg)
				for _, part := range strings.Split(path, ".") {
					for typ.Kind() == reflect.Pointer || typ.Kind() == reflect.Slice {
						typ = typ.Elem()
					}
					if typ.Kind() != reflect.Struct {
						t.Fatalf("non-struct %s.%s", name, path)
					}
					field, ok := typ.FieldByName(part)
					if !ok {
						t.Errorf("unsupported advertised field %s.%s", name, path)
						break
					}
					typ = field.Type
				}
			}
		}
	}
}

func TestAnalystRecordAndJSONBounds(t *testing.T) {
	source, _ := fixture(t, "record-limit")
	f, err := os.Create(filepath.Join(source.Directory, "Connection.ncap.gz"))
	if err != nil {
		t.Fatal(err)
	}
	z := gzip.NewWriter(f)
	w := delimited.NewWriter(z)
	if err = w.PutProto(&types.Header{Type: types.Type_NC_Connection}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i <= MaxRecords; i++ {
		if err = w.PutProto(&types.Connection{}); err != nil {
			t.Fatal(err)
		}
	}
	if err = z.Close(); err != nil {
		t.Fatal(err)
	}
	if err = f.Close(); err != nil {
		t.Fatal(err)
	}
	if err = Walk(context.Background(), source.Directory, source.Binding, "Connection", func(Reference, proto.Message) error { return nil }); err == nil {
		t.Fatal("record bound ignored")
	}
	for _, bad := range []string{`{"source":{},"Source":{}}`, `{"source":{"sessionId":"","inputFile":"owned"}}`, `{"source":{"inputFile":null}}`, `{"source":{}} {}`} {
		var target InspectRequest
		if err = DecodeStrict([]byte(bad), &target); err == nil {
			t.Fatalf("ambiguous input accepted %s", bad)
		}
	}
}

func TestWorkspaceNeverReapsAnotherProcessLock(t *testing.T) {
	source, _ := fixture(t, "locked")
	write(t, source.Directory, WorkspaceLockFile, []byte("other owner"))
	_, err := SaveDocument(context.Background(), source.Directory, source.Binding, Document{Kind: "report", Title: "report", Binding: source.Binding, Review: "draft"}, 0)
	if !errors.Is(err, ErrBusy) {
		t.Fatalf("lock was ignored: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(source.Directory, WorkspaceLockFile))
	if err != nil || string(data) != "other owner" {
		t.Fatal("foreign lock removed")
	}
	if _, err = os.Stat(filepath.Join(source.Directory, WorkspaceFile)); !os.IsNotExist(err) {
		t.Fatal("workspace changed under foreign lock")
	}
}

func TestCatalogueMissingIndicatorFieldsCannotEstablishNovelty(t *testing.T) {
	target, _ := fixture(t, "hash-target")
	baseline, _ := fixture(t, "hash-baseline")
	audit(t, target.Directory, "File", types.Type_NC_File, &types.File{Hashes: &types.FileHashes{SHA256: strings.Repeat("a", 64)}})
	audit(t, baseline.Directory, "File", types.Type_NC_File, &types.File{Name: "legacy-without-qualified-hash"})
	result, err := Search(context.Background(), []Source{target, baseline}, Query{"sha256", strings.Repeat("a", 64), []string{"File"}})
	if err != nil {
		t.Fatal(err)
	}
	if result.Novelty != "unknown" || result.Coverage[1].State != "partial-fields" || result.Coverage[1].UnqualifiedRecords != 1 {
		t.Fatalf("unknown hashes became novelty %+v", result)
	}
	if values := Match(Query{"domain", ".", []string{"DNS"}}, &types.DNS{Questions: []*types.DNSQuestion{{Name: ""}}}, "DNS"); len(values) != 0 {
		t.Fatal("absent name became root-domain evidence")
	}
}

func TestCatalogueSnapshotPagesCannotMixChangedFiles(t *testing.T) {
	source, _ := fixture(t, "pages")
	query := Query{"endpoint", "192.0.2.1", []string{"Connection"}}
	result, err := Search(context.Background(), []Source{source}, query)
	if err != nil {
		t.Fatal(err)
	}
	first, err := Paginate(result, &CataloguePage{Offset: 0, Limit: 1}, "")
	if err != nil || len(first.Occurrences) != 1 || first.TotalOccurrences != 2 || first.NextOffset == nil || *first.NextOffset != 1 {
		t.Fatalf("first page %+v %v", first, err)
	}
	second, err := Paginate(result, &CataloguePage{Offset: 1, Limit: 1}, first.SnapshotSHA256)
	if err != nil || second.Occurrences[0].Reference.Ordinal != "1" || second.NextOffset != nil {
		t.Fatalf("second page %+v %v", second, err)
	}
	if _, err = Paginate(result, &CataloguePage{Offset: 1, Limit: 1}, ""); err == nil {
		t.Fatal("unbound subsequent page accepted")
	}
	audit(t, source.Directory, "Connection", types.Type_NC_Connection, &types.Connection{SrcIP: "192.0.2.1", DstIP: "192.0.2.2", TransportProto: "UDP"})
	changed, err := Search(context.Background(), []Source{source}, query)
	if err != nil {
		t.Fatal(err)
	}
	if changed.SnapshotSHA256 == first.SnapshotSHA256 {
		t.Fatal("changed audit file retained old snapshot")
	}
	if _, err = Paginate(changed, &CataloguePage{Offset: 0, Limit: 1}, first.SnapshotSHA256); !errors.Is(err, ErrStale) {
		t.Fatalf("mixed snapshots %v", err)
	}
}

func TestCatalogueSocketKeepsEndpointPairsAndExplicitTransport(t *testing.T) {
	record := &types.Connection{SrcIP: "192.0.2.1", SrcPort: "52123", DstIP: "192.0.2.2", DstPort: "443", TransportProto: "TCP"}
	for _, tc := range []struct {
		value string
		want  int
	}{{"192.0.2.1:443", 0}, {"192.0.2.2:443", 1}, {"tcp://192.0.2.2:443", 1}, {"udp://192.0.2.2:443", 0}, {"192.0.2.20:443", 0}} {
		q := Query{"endpoint", tc.value, []string{"Connection"}}
		if err := ValidateQuery(q); err != nil {
			t.Fatal(err)
		}
		if got := Match(q, record, "Connection"); len(got) != tc.want {
			t.Fatalf("%s matched %+v", tc.value, got)
		}
	}
	for _, q := range []Query{{"endpoint", "192.0.2.1:0", []string{"Connection"}}, {"endpoint", "tcp://192.0.2.1:443", []string{"DNS"}}, {"endpoint", "192.0.2.1:443", []string{"Software"}}} {
		if ValidateQuery(q) == nil {
			t.Fatalf("unsupported endpoint accepted %+v", q)
		}
	}
}

func TestAtomicWorkspaceRejectsDirectoryReplacementAndFailedValidation(t *testing.T) {
	parent := t.TempDir()
	dir := filepath.Join(parent, "owned")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	write(t, dir, WorkspaceFile, []byte("original"))
	sentinel := errors.New("validation failure")
	if err := AtomicJSON(context.Background(), dir, WorkspaceFile, []byte("changed"), func() error { return sentinel }); !errors.Is(err, sentinel) {
		t.Fatalf("validation lost %v", err)
	}
	data, err := os.ReadFile(filepath.Join(dir, WorkspaceFile))
	if err != nil || string(data) != "original" {
		t.Fatal("failed validation changed workspace")
	}
	old := filepath.Join(parent, "old")
	external := t.TempDir()
	err = AtomicJSON(context.Background(), dir, WorkspaceFile, []byte("changed"), func() error {
		if e := os.Rename(dir, old); e != nil {
			return e
		}
		return os.Symlink(external, dir)
	})
	if err == nil {
		t.Fatal("directory replacement accepted")
	}
	if _, e := os.Stat(filepath.Join(external, WorkspaceFile)); !os.IsNotExist(e) {
		t.Fatal("wrote through replacement symlink")
	}
	data, err = os.ReadFile(filepath.Join(old, WorkspaceFile))
	if err != nil || string(data) != "original" {
		t.Fatal("orphan root was published")
	}
	entries, err := os.ReadDir(old)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".analyst-") {
			t.Fatal("temporary write leaked")
		}
	}
}
