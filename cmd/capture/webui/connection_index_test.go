package webui

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gogo/protobuf/proto"

	"github.com/dreadl0ck/netcap/internal/delimited"
	"github.com/dreadl0ck/netcap/types"
)

func TestConnectionSnapshotScanLimits(t *testing.T) {
	dir := t.TempDir()
	s := newTimelineTestServer(dir)
	request := func(handler http.HandlerFunc) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		handler(w, httptest.NewRequest(http.MethodGet, "/?limit=1", nil))
		return w
	}
	refused := func() {
		t.Helper()
		for _, handle := range []http.HandlerFunc{s.handleConnections, s.handleConnectionsTopByTraffic, s.handleConnectionsProtocols, s.handleConnectionsApplications, s.handleConnectionsDuration} {
			w := request(handle)
			var response map[string]string
			if w.Code != http.StatusRequestEntityTooLarge || json.Unmarshal(w.Body.Bytes(), &response) != nil || len(response) != 1 || response["error"] != errConnectionScanLimit.Error() {
				t.Fatalf("expected only the scan-limit error: %d %s", w.Code, w.Body)
			}
		}
	}
	path := filepath.Join(dir, "Connection.ncap.gz")
	writeTimelineAuditFile(t, dir, "Connection", types.Type_NC_Connection, nil)
	if err := os.Truncate(path, connectionScanBytes+1); err != nil {
		t.Fatal(err)
	}
	refused()

	rows := make([]proto.Message, connectionMaxRows+1)
	for i := range rows {
		rows[i] = &types.Connection{}
	}
	writeTimelineAuditFile(t, dir, "Connection", types.Type_NC_Connection, rows[:connectionMaxRows])
	w := request(s.handleConnections)
	var page ConnectionsResponse
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &page) != nil || page.TotalCount != connectionMaxRows || len(page.Connections) != 1 {
		t.Fatalf("exact row budget: %d %s", w.Code, w.Body)
	}
	writeTimelineAuditFile(t, dir, "Connection", types.Type_NC_Connection, rows)
	w = request(s.handleConnections)
	if w.Code != http.StatusRequestEntityTooLarge || strings.Contains(w.Body.String(), "totalCount") {
		t.Fatalf("row budget exceeded: %d %s", w.Code, w.Body)
	}

	writeTimelineAuditFile(t, dir, "Connection", types.Type_NC_Connection, []proto.Message{
		&types.Connection{SrcIP: strings.Repeat("a", connectionFrameBytes)},
	})
	refused()
}

func TestConnectionSnapshotDecodedByteLimit(t *testing.T) {
	dir := t.TempDir()
	record := &types.Connection{SrcIP: strings.Repeat("a", connectionFrameBytes)}
	record.SrcIP = record.SrcIP[:connectionFrameBytes-(proto.Size(record)-connectionFrameBytes)]
	if proto.Size(record) != connectionFrameBytes {
		t.Fatal("fixture must fill the frame budget exactly")
	}
	rows := make([]proto.Message, connectionScanBytes/connectionFrameBytes+1)
	for i := range rows {
		rows[i] = record
	}
	rows[len(rows)-1] = &types.Connection{TotalSize: 1}
	writeTimelineAuditFile(t, dir, "Connection", types.Type_NC_Connection, rows[:len(rows)-1])
	read := func() ([]ConnectionSummary, error) {
		info, err := connectionGeneration(dir)
		if err != nil {
			t.Fatal(err)
		}
		return readConnectionGeneration(dir, info)
	}
	if got, err := read(); len(got) != len(rows)-1 || err != nil {
		t.Fatalf("exact body budget: rows=%d err=%v", len(got), err)
	}
	writeTimelineAuditFile(t, dir, "Connection", types.Type_NC_Connection, rows)
	if got, err := read(); got != nil || !errors.Is(err, errConnectionScanLimit) {
		t.Fatalf("over body budget: rows=%d err=%v", len(got), err)
	}
}

func TestConnectionSnapshotCacheChargesRetainedDNSNames(t *testing.T) {
	first, second := t.TempDir(), t.TempDir()
	t.Cleanup(func() {
		connectionCache.Lock()
		defer connectionCache.Unlock()
		for _, dir := range []string{first, second} {
			if entry := connectionCache.entries[dir]; entry != nil {
				connectionCache.bytes -= entry.snapshot.bytes
				delete(connectionCache.entries, dir)
			}
		}
	})
	record := &types.Connection{DNSResolvedName: strings.Repeat("a", 512<<10)}
	rows := make([]proto.Message, 66)
	for i := range rows {
		rows[i] = record
	}
	writeTimelineAuditFile(t, first, "Connection", types.Type_NC_Connection, rows)
	writeTimelineAuditFile(t, second, "Connection", types.Type_NC_Connection, rows)
	for _, dir := range []string{first, second} {
		snapshot, err := connectionSnapshotFor(dir)
		if err != nil || len(snapshot.rows) != len(rows) || snapshot.rows[0].DNSResolvedName != record.DNSResolvedName {
			t.Fatalf("snapshot failed for %s: %v", dir, err)
		}
	}
	connectionCache.Lock()
	defer connectionCache.Unlock()
	if connectionCache.entries[first] != nil || connectionCache.entries[second] == nil || connectionCache.bytes > connectionCacheBytes {
		t.Fatalf("expected only the newer 33 MiB snapshot to survive: first=%t second=%t bytes=%d",
			connectionCache.entries[first] != nil, connectionCache.entries[second] != nil, connectionCache.bytes)
	}
}

func TestConnectionSnapshotRefusesExpandedBackingData(t *testing.T) {
	dir := t.TempDir()
	record := &types.Connection{Applications: make([]string, 200_000)}
	rows := make([]proto.Message, 64)
	for i := range rows {
		rows[i] = record
	}
	if size := proto.Size(record); size == 0 || size > connectionFrameBytes || size*len(rows) > connectionScanBytes {
		t.Fatalf("fixture must fit the wire scan limits: %d bytes per record", size)
	}
	writeTimelineAuditFile(t, dir, "Connection", types.Type_NC_Connection, rows)
	s := newTimelineTestServer(dir)
	request := func() *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		s.handleConnections(w, httptest.NewRequest(http.MethodGet, "/?limit=1&host=not-present", nil))
		return w
	}
	w := request()
	var failure map[string]string
	if w.Code != http.StatusRequestEntityTooLarge || json.Unmarshal(w.Body.Bytes(), &failure) != nil || len(failure) != 1 || failure["error"] != errConnectionBackingLimit.Error() {
		t.Fatalf("expected only the backing-limit error: %d %s", w.Code, w.Body)
	}
	writeTimelineAuditFile(t, dir, "Connection", types.Type_NC_Connection, []proto.Message{&types.Connection{SrcIP: "not-present"}})
	w = request()
	var page ConnectionsResponse
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &page) != nil || page.TotalCount != 1 || len(page.Connections) != 1 {
		t.Fatalf("replacement audit did not recover: %d %s", w.Code, w.Body)
	}
}

func TestConnectionSnapshotBuildLimitKeepsCacheHitsAvailable(t *testing.T) {
	warm, cold := t.TempDir(), t.TempDir()
	initial, err := connectionSnapshotFor(warm)
	if err != nil {
		t.Fatal(err)
	}
	func() {
		for range cap(connectionBuildSlots) {
			connectionBuildSlots <- struct{}{}
			defer func() { <-connectionBuildSlots }()
		}
		if got, err := connectionSnapshotFor(warm); got != initial || err != nil {
			t.Fatalf("warm snapshot at capacity: got=%p want=%p err=%v", got, initial, err)
		}
		w := httptest.NewRecorder()
		newTimelineTestServer(cold).handleConnections(w, httptest.NewRequest("GET", "/api/connections?limit=1", nil))
		if w.Code != 429 {
			t.Fatalf("cold snapshot at capacity: %d %s", w.Code, w.Body)
		}
	}()
	if got, err := connectionSnapshotFor(cold); got == nil || err != nil {
		t.Fatalf("cold retry after release: got=%p err=%v", got, err)
	}
}

func TestConnectionResponsesShareCapacityThroughWrite(t *testing.T) {
	s := newTimelineTestServer(t.TempDir())
	request := func() *http.Request { return httptest.NewRequest(http.MethodGet, "/?limit=1", nil) }
	charts := []http.HandlerFunc{s.handleConnectionsTopByTraffic, s.handleConnectionsProtocols, s.handleConnectionsApplications, s.handleConnectionsDuration}
	release := make(chan struct{})
	var workers sync.WaitGroup
	finish := sync.OnceFunc(func() { close(release); workers.Wait() })
	t.Cleanup(finish)
	var responses []*httptest.ResponseRecorder
	for _, handle := range charts {
		w := heldAlertPageResponse{ResponseRecorder: httptest.NewRecorder(), writing: make(chan struct{}, 1), release: release}
		responses = append(responses, w.ResponseRecorder)
		workers.Go(func() { handle(w, request()) })
		select {
		case <-w.writing:
		case <-time.After(5 * time.Second):
			t.Fatal("chart did not reach its response write")
		}
	}
	w := httptest.NewRecorder()
	s.handleConnections(w, request())
	if w.Code != http.StatusTooManyRequests || !strings.Contains(w.Body.String(), "responses are busy") {
		t.Fatalf("inventory with four chart writes in flight: %d %s", w.Code, w.Body)
	}
	finish()
	for i, response := range responses {
		if response.Code != http.StatusOK || response.Header().Get("Content-Type") != "text/html" {
			t.Fatalf("chart %d: %d %s", i, response.Code, response.Header().Get("Content-Type"))
		}
	}
	w = httptest.NewRecorder()
	s.handleConnections(w, request())
	if w.Code != http.StatusOK {
		t.Fatalf("inventory retry: %d %s", w.Code, w.Body)
	}
}

func TestConnectionSnapshotWaitCanCancelWithoutRetiringBuild(t *testing.T) {
	dir := t.TempDir()
	entry := &connectionCacheEntry{ready: make(chan struct{})}
	connectionCache.Lock()
	connectionCache.entries[dir] = entry
	connectionCache.Unlock()
	t.Cleanup(func() {
		connectionCache.Lock()
		delete(connectionCache.entries, dir)
		connectionCache.Unlock()
	})
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if snapshot, err := connectionSnapshotForContext(ctx, dir); snapshot != nil || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("waiting request: snapshot=%v err=%v", snapshot, err)
	}
	connectionCache.Lock()
	kept := connectionCache.entries[dir] == entry
	connectionCache.Unlock()
	if !kept {
		t.Fatal("canceled waiter retired the shared build")
	}
	entry.err = errors.New("fixture snapshot build failed")
	close(entry.ready)
	if snapshot, err := connectionSnapshotFor(dir); snapshot != nil || !errors.Is(err, entry.err) {
		t.Fatalf("failed build: snapshot=%v err=%v", snapshot, err)
	}
}

func TestConnectionIndexFiltersCountsAndPagination(t *testing.T) {
	dir := t.TempDir()
	writeTimelineAuditFile(t, dir, "Connection", types.Type_NC_Connection, []proto.Message{
		&types.Connection{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", CommunityID: "one", NetworkProto: "IPv4", TransportProto: "TCP", ApplicationProto: "HTTP", TotalSize: 10},
		&types.Connection{SrcIP: "10.0.0.2", DstIP: "10.0.0.3", CommunityID: "two", NetworkProto: "IPv4", TransportProto: "TCP", ApplicationProto: "HTTP", TotalSize: 40},
		&types.Connection{SrcIP: "10.0.0.4", DstIP: "10.0.0.1", CommunityID: "two", NetworkProto: "IPv6", TransportProto: "", TotalSize: 20},
	})
	s := newTimelineTestServer(dir)
	request := func(q string) ConnectionsResponse {
		t.Helper()
		rec := httptest.NewRecorder()
		s.handleConnections(rec, httptest.NewRequest("GET", "/api/connections?"+q, nil))
		if rec.Code != 200 {
			t.Fatalf("%q status = %d: %s", q, rec.Code, rec.Body.String())
		}
		var result ConnectionsResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		return result
	}
	for _, tc := range []struct {
		query string
		count int
		first int32
	}{
		{"", 3, 40},
		{"communityId=one&communityId=two&host=10.0.0.1", 2, 20},
		{"communityId=two&srcIP=10.0.0.4&dstIP=10.0.0.1&ipVersion=ipv6", 1, 20},
		{"protocol=HTTP&layer=transport&ipVersion=ipv4", 2, 40},
		{"communityId=missing", 0, 0},
	} {
		got := request(tc.query)
		if got.TotalCount != tc.count || len(got.Connections) != tc.count || tc.count > 0 && got.Connections[0].TotalSize != tc.first {
			t.Errorf("%q = %+v", tc.query, got)
		}
	}
	page := request("communityId=one&communityId=two&host=10.0.0.1&limit=1&offset=1")
	if page.TotalCount != 2 || len(page.Connections) != 1 || page.Connections[0].TotalSize != 10 {
		t.Fatalf("page = %+v", page)
	}
	for _, query := range []string{"limit=0", "limit=1001", "offset=-1"} {
		rec := httptest.NewRecorder()
		s.handleConnections(rec, httptest.NewRequest("GET", "/api/connections?"+query, nil))
		if rec.Code != 400 {
			t.Errorf("%q status = %d, want 400", query, rec.Code)
		}
	}
}

func TestConnectionIndexInvalidatesAndSharesBuild(t *testing.T) {
	dir := t.TempDir()
	writeTimelineAuditFile(t, dir, "Connection", types.Type_NC_Connection, []proto.Message{&types.Connection{CommunityID: "old"}})
	results := make([]*connectionSnapshot, 12)
	var wg sync.WaitGroup
	for i := range results {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			var err error
			results[i], err = connectionSnapshotFor(dir)
			if err != nil {
				t.Errorf("snapshot: %v", err)
			}
		}(i)
	}
	wg.Wait()
	for _, snapshot := range results {
		if snapshot == nil || snapshot != results[0] {
			t.Fatal("concurrent builds were not shared")
		}
	}
	writeTimelineAuditFile(t, dir, "Connection", types.Type_NC_Connection, []proto.Message{
		&types.Connection{CommunityID: "new"}, &types.Connection{CommunityID: "new"},
	})
	updated, err := connectionSnapshotFor(dir)
	if err != nil || updated == results[0] || updated.selectRows(connectionFilter{communityIDs: map[string]bool{"old": true}}).TotalCount != 0 ||
		updated.selectRows(connectionFilter{communityIDs: map[string]bool{"new": true}}).TotalCount != 2 {
		t.Fatalf("stale snapshot: %+v, %v", updated, err)
	}
}

func TestConnectionIndexInvalidatesSameSizeReplacement(t *testing.T) {
	dir, replacement := t.TempDir(), t.TempDir()
	const name = "Connection.ncap.gz"
	writeTimelineAuditFile(t, dir, "Connection", types.Type_NC_Connection, []proto.Message{&types.Connection{CommunityID: "old"}})
	writeTimelineAuditFile(t, replacement, "Connection", types.Type_NC_Connection, []proto.Message{&types.Connection{CommunityID: "new"}})
	path, next := filepath.Join(dir, name), filepath.Join(replacement, name)
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	old, err := connectionSnapshotFor(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(next, before.ModTime(), before.ModTime()); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(next, path); err != nil {
		t.Fatal(err)
	}
	after, err := os.Stat(path)
	if err != nil || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) || os.SameFile(before, after) {
		t.Fatalf("fixture did not replace the file while preserving size and mtime: %v", err)
	}
	if rows, err := readConnectionGeneration(dir, before); rows != nil || !errors.Is(err, errConnectionAuditChanged) {
		t.Fatalf("build opened the replacement for the old generation: rows=%v err=%v", rows, err)
	}
	got, err := connectionSnapshotFor(dir)
	if err != nil || got == old || len(got.rows) != 1 || got.rows[0].CommunityID != "new" {
		t.Fatalf("replacement did not invalidate cache: snapshot=%v error=%v", got, err)
	}
}

func TestConnectionIndexFallbackAgreesWithScan(t *testing.T) {
	rows := make([]ConnectionSummary, connectionMaxKeys+1)
	for i := range rows {
		rows[i] = ConnectionSummary{SrcIP: fmt.Sprintf("host-%d", i), CommunityID: "shared", TransportProto: "TCP"}
	}
	snapshot := newConnectionSnapshot(rows)
	if snapshot.byID != nil {
		t.Fatal("high-cardinality snapshot built a partial index")
	}
	for _, query := range []string{"communityId=shared&host=host-8192", "communityId=shared&host=host-0&protocol=TCP", "communityId=missing"} {
		opts, err := parseConnectionFilter(mustParseQuery(t, query))
		if err != nil {
			t.Fatal(err)
		}
		got := snapshot.selectRows(opts)
		var want int
		for _, row := range rows {
			if opts.match(row) {
				want++
			}
		}
		if got.TotalCount != want {
			t.Errorf("%q: got %d, want %d", query, got.TotalCount, want)
		}
	}
}

func mustParseQuery(t *testing.T, query string) url.Values {
	t.Helper()
	values, err := url.ParseQuery(query)
	if err != nil {
		t.Fatal(err)
	}
	return values
}

func BenchmarkConnectionFilteredRequest(b *testing.B) {
	dir := b.TempDir()
	f, err := os.Create(filepath.Join(dir, "Connection.ncap.gz"))
	if err != nil {
		b.Fatal(err)
	}
	gz := gzip.NewWriter(f)
	w := delimited.NewWriter(gz)
	if err := w.PutProto(&types.Header{Type: types.Type_NC_Connection}); err != nil {
		b.Fatal(err)
	}
	for i := range 10_000 {
		if err := w.PutProto(&types.Connection{CommunityID: fmt.Sprintf("id-%d", i%200), SrcIP: fmt.Sprintf("host-%d", i%100), TotalSize: int32(i)}); err != nil {
			b.Fatal(err)
		}
	}
	if err := gz.Close(); err != nil {
		b.Fatal(err)
	}
	if err := f.Close(); err != nil {
		b.Fatal(err)
	}
	opts, err := parseConnectionFilter(url.Values{"communityId": {"id-1"}})
	if err != nil {
		b.Fatal(err)
	}
	if _, err := connectionSnapshotFor(dir); err != nil {
		b.Fatal(err)
	}
	b.Run("scan", func(b *testing.B) {
		for range b.N {
			rows, err := readConnections(dir)
			if err != nil {
				b.Fatal(err)
			}
			got := 0
			for _, row := range rows {
				if opts.match(row) {
					got++
				}
			}
			if got != 50 {
				b.Fatalf("count = %d", got)
			}
		}
	})
	b.Run("cached", func(b *testing.B) {
		for range b.N {
			snapshot, err := connectionSnapshotFor(dir)
			if err != nil {
				b.Fatal(err)
			}
			if got := snapshot.selectRows(opts).TotalCount; got != 50 {
				b.Fatalf("count = %d", got)
			}
		}
	})
	b.Run("four-charts-scan", func(b *testing.B) {
		for range b.N {
			for range 4 {
				if _, err := readConnections(dir); err != nil {
					b.Fatal(err)
				}
			}
		}
	})
	b.Run("four-charts-cached", func(b *testing.B) {
		for range b.N {
			for range 4 {
				if snapshot, err := connectionSnapshotFor(dir); err != nil || len(snapshot.rows) != 10_000 {
					b.Fatal("incomplete chart data")
				}
			}
		}
	})
}
