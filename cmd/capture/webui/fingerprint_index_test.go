package webui

import (
	"compress/gzip"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"

	"github.com/gogo/protobuf/proto"

	"github.com/dreadl0ck/netcap/internal/delimited"
	"github.com/dreadl0ck/netcap/types"
)

func TestFingerprintSnapshotFiltersAndMenuCounts(t *testing.T) {
	dir := t.TempDir()
	writeTimelineAuditFile(t, dir, "HTTP", types.Type_NC_HTTP, []proto.Message{
		&types.HTTP{Ja4H: "chrome", CommunityID: "one", SrcIP: "10.0.0.1", Timestamp: 1},
		&types.HTTP{Ja4H: "chrome", CommunityID: "two", SrcIP: "10.0.0.2", Timestamp: 2},
		&types.HTTP{Ja4H: "firefox", CommunityID: "two", Timestamp: 3},
		&types.HTTP{Ja4H: "server", CommunityID: "three", Timestamp: 4},
	})
	snapshot, err := fingerprintSnapshotFor(dir)
	if err != nil || snapshot.byID == nil || snapshot.stats.TotalOccurrences != 4 {
		t.Fatalf("snapshot = (%+v, %v)", snapshot, err)
	}
	for _, tc := range []struct {
		ids  map[string]bool
		want int64
	}{
		{map[string]bool{"one": true, "two": true}, 2},
		{map[string]bool{"missing": true}, 0},
	} {
		if got := snapshot.count(tc.ids); got != tc.want {
			t.Errorf("count(%v) = %d, want %d", tc.ids, got, tc.want)
		}
	}

	opts := fingerprintListOptions{
		typeFilter: "JA4H", search: "chrome !firefox",
		communityIDFilter: map[string]struct{}{"one": {}, "two": {}},
	}
	if got, want := snapshot.filter(opts), filterFingerprints(snapshot.rows, opts); !reflect.DeepEqual(got, want) {
		t.Fatalf("bitmap filter = %+v, scan = %+v", got, want)
	}
	if got := snapshot.filter(fingerprintListOptions{communityIDFilter: map[string]struct{}{"missing": {}}}); len(got) != 0 {
		t.Fatalf("unknown ID returned %+v", got)
	}

	s := newTimelineTestServer(dir)
	request := func(path string) FingerprintsResponse {
		t.Helper()
		rec := httptest.NewRecorder()
		s.handleFingerprints(rec, httptest.NewRequest("GET", path, nil))
		if rec.Code != 200 {
			t.Fatalf("%s: status %d: %s", path, rec.Code, rec.Body.String())
		}
		var result FingerprintsResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		return result
	}
	page := request("/api/fingerprints?communityId=two&sortField=count&limit=1")
	if page.TotalCount != 2 || page.Stats.TotalFingerprints != 3 || len(page.Fingerprints) != 1 || page.Fingerprints[0].Fingerprint != "chrome" || page.Fingerprints[0].CommunityIDs[0] != "two" {
		t.Fatalf("paginated fingerprints = %+v", page)
	}
	if got := s.getFilteredMenuCounts(dir, map[string]bool{"one": true, "two": true}).FingerprintsCount; got != 2 {
		t.Fatalf("menu fingerprints count = %d, want 2", got)
	}
}

func TestFingerprintSnapshotInvalidatesAndSharesBuild(t *testing.T) {
	dir := t.TempDir()
	writeTimelineAuditFile(t, dir, "HTTP", types.Type_NC_HTTP, []proto.Message{&types.HTTP{Ja4H: "first", CommunityID: "one"}})
	var wg sync.WaitGroup
	results := make([]*fingerprintSnapshot, 12)
	for i := range results {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			var err error
			results[i], err = fingerprintSnapshotFor(dir)
			if err != nil {
				t.Errorf("snapshot: %v", err)
			}
		}(i)
	}
	wg.Wait()
	for _, got := range results {
		if got != results[0] || got == nil {
			t.Fatal("concurrent requests did not share the same snapshot")
		}
	}
	writeTimelineAuditFile(t, dir, "HTTP", types.Type_NC_HTTP, []proto.Message{
		&types.HTTP{Ja4H: "second", CommunityID: "two"},
		&types.HTTP{Ja4H: "second", CommunityID: "two"},
	})
	updated, err := fingerprintSnapshotFor(dir)
	if err != nil || updated == results[0] || updated.count(map[string]bool{"one": true}) != 0 || updated.count(map[string]bool{"two": true}) != 1 || updated.stats.TotalOccurrences != 2 {
		t.Fatalf("stale fingerprint snapshot: %+v, %v", updated, err)
	}
	writeTimelineAuditFile(t, dir, "SSH", types.Type_NC_SSH, []proto.Message{&types.SSH{Ja4Ssh: "ssh-fp", CommunityID: "three"}})
	withSSH, err := fingerprintSnapshotFor(dir)
	if err != nil || withSSH == updated || withSSH.count(map[string]bool{"three": true}) != 1 || len(withSSH.rows) != 2 {
		t.Fatalf("new fingerprint source was not indexed: %+v, %v", withSSH, err)
	}
}

func TestFingerprintBitmapFallbackMatchesScan(t *testing.T) {
	rows := make([]FingerprintSummary, fingerprintMaxRows+1)
	for i := range rows {
		rows[i] = FingerprintSummary{Fingerprint: "same", Type: "JA4", CommunityIDs: []string{"one", "two"}}
	}
	snapshot := newFingerprintSnapshot(rows)
	if snapshot.byID != nil {
		t.Fatal("oversized snapshot should not build a bitmap")
	}
	opts := fingerprintListOptions{communityIDFilter: map[string]struct{}{"one": {}, "two": {}}}
	if got := snapshot.filter(opts); len(got) != len(rows) {
		t.Fatalf("fallback rows = %d, want %d", len(got), len(rows))
	}
	if got := snapshot.count(map[string]bool{"one": true, "two": true}); got != int64(len(rows)) {
		t.Fatalf("fallback unique count = %d, want %d", got, len(rows))
	}
	rows = make([]FingerprintSummary, fingerprintMaxIDs+1)
	for i := range rows {
		rows[i] = FingerprintSummary{CommunityIDs: []string{fmt.Sprintf("id-%d", i)}}
	}
	snapshot = newFingerprintSnapshot(rows)
	if snapshot.byID != nil || snapshot.count(map[string]bool{"id-4096": true}) != 1 {
		t.Fatal("high-cardinality fallback lost the last ID")
	}
}

func BenchmarkFingerprintFilteredRequest(b *testing.B) {
	dir := b.TempDir()
	for name, typ := range map[string]types.Type{
		"SSH": types.Type_NC_SSH, "TLSClientHello": types.Type_NC_TLSClientHello,
		"TLSServerHello": types.Type_NC_TLSServerHello, "Host": types.Type_NC_Host,
		"DHCPv4": types.Type_NC_DHCPv4, "TLSCertificate": types.Type_NC_TLSCertificate,
		"TCP": types.Type_NC_TCP,
	} {
		file, err := os.Create(filepath.Join(dir, name+".ncap.gz"))
		if err != nil {
			b.Fatal(err)
		}
		writer := gzip.NewWriter(file)
		if err := delimited.NewWriter(writer).PutProto(&types.Header{Type: typ}); err != nil {
			b.Fatal(err)
		}
		if err := writer.Close(); err != nil {
			b.Fatal(err)
		}
		if err := file.Close(); err != nil {
			b.Fatal(err)
		}
	}
	f, err := os.Create(filepath.Join(dir, "HTTP.ncap.gz"))
	if err != nil {
		b.Fatal(err)
	}
	gz := gzip.NewWriter(f)
	w := delimited.NewWriter(gz)
	if err := w.PutProto(&types.Header{Type: types.Type_NC_HTTP}); err != nil {
		b.Fatal(err)
	}
	for i := range 10_000 {
		if err := w.PutProto(&types.HTTP{Ja4H: fmt.Sprintf("fingerprint-%d", i%500), CommunityID: fmt.Sprintf("id-%d", i%200), Timestamp: int64(i)}); err != nil {
			b.Fatal(err)
		}
	}
	if err := gz.Close(); err != nil {
		b.Fatal(err)
	}
	if err := f.Close(); err != nil {
		b.Fatal(err)
	}
	s := newTimelineTestServer(dir)
	url := "/api/fingerprints?communityId=id-1&communityId=id-2&sortField=count&limit=100"
	request := httptest.NewRequest("GET", url, nil)
	if _, err := fingerprintSnapshotFor(dir); err != nil {
		b.Fatal(err)
	}
	b.Run("scan-and-aggregate", func(b *testing.B) {
		for range b.N {
			rows, err := readFingerprints(dir)
			if err != nil {
				b.Fatal(err)
			}
			filtered := filterFingerprints(rows, parseFingerprintListOptions(request.URL.Query()))
			sortFingerprints(filtered, "count", "desc")
			if len(filtered) == 0 {
				b.Fatal("expected filtered fingerprints")
			}
		}
	})
	b.Run("cached-handler", func(b *testing.B) {
		for range b.N {
			rec := httptest.NewRecorder()
			s.handleFingerprints(rec, request)
			if rec.Code != 200 {
				b.Fatalf("status %d: %s", rec.Code, rec.Body.String())
			}
		}
	})
	b.Run("four-charts-scan", func(b *testing.B) {
		for range b.N {
			for range 4 {
				if _, err := readFingerprints(dir); err != nil {
					b.Fatal(err)
				}
			}
		}
	})
	b.Run("four-charts-snapshot", func(b *testing.B) {
		for range b.N {
			for range 4 {
				if _, err := fingerprintSnapshotFor(dir); err != nil {
					b.Fatal(err)
				}
			}
		}
	})
}
