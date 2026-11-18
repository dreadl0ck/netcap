package webui

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gogo/protobuf/proto"

	"github.com/dreadl0ck/netcap/internal/delimited"
	"github.com/dreadl0ck/netcap/types"
)

func TestFingerprintInventoryLimitsConcurrentWarmResponses(t *testing.T) {
	dir := t.TempDir()
	writeTimelineAuditFile(t, dir, "HTTP", types.Type_NC_HTTP, []proto.Message{&types.HTTP{Ja4H: "fixture"}})
	if _, err := fingerprintSnapshotFor(dir); err != nil {
		t.Fatal(err)
	}
	testInventoryResponseCapacity(t, "/api/fingerprints", newTimelineTestServer(dir).handleFingerprints)
}

func TestFingerprintPagesKeepTiedTypesInOrderAcrossRebuilds(t *testing.T) {
	dir := t.TempDir()
	s := newTimelineTestServer(dir)
	for stamp := int64(1); stamp <= 4; stamp++ {
		writeTimelineAuditFile(t, dir, "HTTP", types.Type_NC_HTTP, []proto.Message{&types.HTTP{Ja4H: "shared", Timestamp: stamp}})
		writeTimelineAuditFile(t, dir, "SSH", types.Type_NC_SSH, []proto.Message{&types.SSH{Ja4Ssh: "shared", Timestamp: stamp}})
		for _, field := range []string{"count", "fingerprint", "hosts"} {
			for offset, want := range []string{"JA4H", "JA4SSH"} {
				w := httptest.NewRecorder()
				path := fmt.Sprintf("/api/fingerprints?limit=1&offset=%d&sortField=%s", offset, field)
				s.handleFingerprints(w, httptest.NewRequest(http.MethodGet, path, nil))
				var page FingerprintsResponse
				if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &page) != nil || page.TotalCount != 2 ||
					len(page.Fingerprints) != 1 || page.Fingerprints[0].Type != want || page.Fingerprints[0].FirstSeen != stamp {
					t.Fatalf("rebuild %d, %s: expected %s, got %d %s", stamp, path, want, w.Code, w.Body)
				}
			}
		}
	}
}

func TestFingerprintSnapshotWaitCanCancelWithoutRetiringBuild(t *testing.T) {
	dir := t.TempDir()
	entry := &fingerprintCacheEntry{ready: make(chan struct{})}
	fingerprintCache.Lock()
	fingerprintCache.entries[dir] = entry
	fingerprintCache.Unlock()
	t.Cleanup(func() {
		fingerprintCache.Lock()
		delete(fingerprintCache.entries, dir)
		fingerprintCache.Unlock()
	})
	ctx, cancel := context.WithTimeout(t.Context(), 25*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := fingerprintSnapshotForContext(ctx, dir)
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("waiting request: %v", err)
		}
	case <-time.After(5 * time.Second):
		close(entry.ready)
		t.Fatal("request waited for the shared build after its deadline")
	}
	fingerprintCache.Lock()
	kept := fingerprintCache.entries[dir] == entry
	fingerprintCache.Unlock()
	if !kept {
		t.Fatal("canceled request retired the shared build")
	}
	entry.err = errors.New("fixture build failed")
	close(entry.ready)
	if got, err := fingerprintSnapshotFor(dir); got != nil || !errors.Is(err, entry.err) {
		t.Fatalf("shared failure: snapshot=%v err=%v", got, err)
	}
}

func TestFingerprintAuditRejectsGrowthBeforeEOF(t *testing.T) {
	dir := t.TempDir()
	writeTimelineAuditFile(t, dir, "HTTP", types.Type_NC_HTTP, []proto.Message{&types.HTTP{Ja4H: "initial"}})
	generation, err := fingerprintGeneration(dir)
	if err != nil {
		t.Fatal(err)
	}
	budget := fingerprintGenerationBudget(generation)
	path := filepath.Join(dir, "HTTP.ncap.gz")
	r, err := budget.open(path, types.Type_NC_HTTP)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if msg, err := budget.next(r); err != nil || msg.(*types.HTTP).Ja4H != "initial" {
		t.Fatalf("initial record: %v, %v", msg, err)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.Write([]byte{0})
	if err := errors.Join(err, f.Close()); err != nil {
		t.Fatal(err)
	}
	if msg, err := budget.next(r); msg != nil || !errors.Is(err, errFingerprintAuditChanged) {
		t.Fatalf("changed source reached EOF: %v, %v", msg, err)
	}
}

func TestFingerprintSnapshotRejectsSameMetadataReplacement(t *testing.T) {
	dir, replacement := t.TempDir(), t.TempDir()
	for path, value := range map[string]string{dir: "aaaa", replacement: "bbbb"} {
		writeTimelineAuditFile(t, path, "HTTP", types.Type_NC_HTTP, []proto.Message{&types.HTTP{Ja4H: value}})
	}
	old, err := fingerprintGeneration(dir)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot, err := fingerprintSnapshotFor(dir); err != nil || len(snapshot.rows) != 1 || snapshot.rows[0].Fingerprint != "aaaa" {
		t.Fatalf("initial snapshot: %v, %v", snapshot, err)
	}
	path, incoming := filepath.Join(dir, "HTTP.ncap.gz"), filepath.Join(replacement, "HTTP.ncap.gz")
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(incoming, info.ModTime(), info.ModTime()); err != nil {
		t.Fatal(err)
	}
	next, err := os.Stat(incoming)
	if err != nil || next.Size() != info.Size() || !next.ModTime().Equal(info.ModTime()) {
		t.Fatalf("replacement metadata differs: %v, %v", next, err)
	}
	if err := os.Rename(incoming, path); err != nil {
		t.Fatal(err)
	}
	if rows, err := readFingerprintGeneration(dir, old); rows != nil || !errors.Is(err, errFingerprintAuditChanged) {
		t.Fatalf("old generation: %v, %v", rows, err)
	}
	if snapshot, err := fingerprintSnapshotFor(dir); err != nil || len(snapshot.rows) != 1 || snapshot.rows[0].Fingerprint != "bbbb" {
		t.Fatalf("replacement snapshot: %v, %v", snapshot, err)
	}
}

func TestFingerprintSnapshotBuildAdmissionKeepsWarmInventoryAvailable(t *testing.T) {
	warm, cold := t.TempDir(), t.TempDir()
	writeTimelineAuditFile(t, warm, "HTTP", types.Type_NC_HTTP, []proto.Message{&types.HTTP{Ja4H: "warm"}})
	request := func(dir string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		newTimelineTestServer(dir).handleFingerprints(w, httptest.NewRequest(http.MethodGet, "/api/fingerprints?limit=1", nil))
		return w
	}
	if w := request(warm); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "warm") {
		t.Fatalf("could not prime snapshot: %d %s", w.Code, w.Body)
	}
	func() {
		for range cap(fingerprintBuildSlots) {
			fingerprintBuildSlots <- struct{}{}
			defer func() { <-fingerprintBuildSlots }()
		}
		if w := request(cold); w.Code != http.StatusTooManyRequests {
			t.Fatalf("cold inventory at capacity: %d %s", w.Code, w.Body)
		}
		if w := request(warm); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "warm") {
			t.Fatalf("warm inventory at capacity: %d %s", w.Code, w.Body)
		}
	}()
	if w := request(cold); w.Code != http.StatusOK {
		t.Fatalf("cold retry: %d %s", w.Code, w.Body)
	}
}

func TestFingerprintInventorySharesScanBudget(t *testing.T) {
	dir := t.TempDir()
	ssh := &types.SSH{Ja4Ssh: "fixture-ssh"}
	web := &types.HTTP{Ja4H: "fixture-http"}
	writeTimelineAuditFile(t, dir, "SSH", types.Type_NC_SSH, []proto.Message{ssh})
	writeTimelineAuditFile(t, dir, "HTTP", types.Type_NC_HTTP, []proto.Message{web})
	var stored int64
	for _, name := range []string{"SSH", "HTTP"} {
		info, err := os.Stat(filepath.Join(dir, name+".ncap.gz"))
		if err != nil {
			t.Fatal(err)
		}
		stored += info.Size()
	}
	exact := inventoryAuditBudget{ctx: context.Background(), stored: stored, bodies: proto.Size(ssh) + proto.Size(web), rows: 2}
	copyBudget := exact
	rows, err := readFingerprintInventory(dir, &copyBudget)
	if err != nil || len(rows) != 2 {
		t.Fatalf("exact shared budget: %v, %v", rows, err)
	}
	for _, short := range []func(*inventoryAuditBudget){
		func(b *inventoryAuditBudget) { b.stored-- },
		func(b *inventoryAuditBudget) { b.bodies-- },
		func(b *inventoryAuditBudget) { b.rows-- },
	} {
		b := exact
		short(&b)
		if rows, err := readFingerprintInventory(dir, &b); rows != nil || !errors.Is(err, errInventoryAuditLimit) {
			t.Fatalf("short shared budget returned %v, %v", rows, err)
		}
	}
	web.Ja4H = strings.Repeat("x", 1<<20)
	writeTimelineAuditFile(t, dir, "HTTP", types.Type_NC_HTTP, []proto.Message{web})
	w := httptest.NewRecorder()
	newTimelineTestServer(dir).handleFingerprints(w, httptest.NewRequest(http.MethodGet, "/api/fingerprints?limit=1", nil))
	if w.Code != http.StatusRequestEntityTooLarge || strings.Contains(w.Body.String(), "fixture-ssh") {
		t.Fatalf("oversized frame: %d %s", w.Code, w.Body)
	}
}

func TestFingerprintInventoryRejectsCorruptTrackAndRecovers(t *testing.T) {
	dir := t.TempDir()
	writeTimelineAuditFile(t, dir, "SSH", types.Type_NC_SSH, []proto.Message{&types.SSH{Ja4Ssh: "valid-ssh"}})
	rows := []proto.Message{&types.HTTP{Ja4H: "valid-http"}}
	writeTimelineAuditFile(t, dir, "HTTP", types.Type_NC_HTTP, rows)
	path := filepath.Join(dir, "HTTP.ncap.gz")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	data[len(data)-8] ^= 1
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	s := newTimelineTestServer(dir)
	request := func() *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		s.handleFingerprints(w, httptest.NewRequest(http.MethodGet, "/api/fingerprints?limit=1", nil))
		return w
	}
	w := request()
	if w.Code != http.StatusInternalServerError || w.Body.String() != "Failed to read fingerprints\n" {
		t.Fatalf("damaged track produced an unexpected response: %d %s", w.Code, w.Body)
	}
	writeTimelineAuditFile(t, dir, "HTTP", types.Type_NC_HTTP, rows)
	w = request()
	var page FingerprintsResponse
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &page) != nil || page.TotalCount != 2 || len(page.Fingerprints) != 1 {
		t.Fatalf("retry did not recover the full inventory: %d %s", w.Code, w.Body)
	}
}

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
