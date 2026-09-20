/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 */

package webui

import (
	"compress/gzip"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/gogo/protobuf/proto"

	"github.com/dreadl0ck/netcap/defaults"
	"github.com/dreadl0ck/netcap/internal/delimited"
	"github.com/dreadl0ck/netcap/types"
)

// writeTimelineAuditFile writes a minimal .ncap.gz audit record file.
func writeTimelineAuditFile(t *testing.T, dir, typeName string, typ types.Type, records []proto.Message) string {
	t.Helper()

	path := filepath.Join(dir, typeName+defaults.FileExtension+".gz")

	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create %s: %v", path, err)
	}
	defer f.Close()

	gz := gzip.NewWriter(f)
	w := delimited.NewWriter(gz)

	if err = w.PutProto(&types.Header{Type: typ, Created: 1, Version: "test"}); err != nil {
		t.Fatalf("write header: %v", err)
	}

	for _, r := range records {
		if err = w.PutProto(r); err != nil {
			t.Fatalf("write record: %v", err)
		}
	}

	if err = gz.Close(); err != nil {
		t.Fatalf("close gzip: %v", err)
	}

	return path
}

func writeTimelineAuditFilePlain(t *testing.T, dir, typeName string, typ types.Type, records []proto.Message) string {
	t.Helper()

	path := filepath.Join(dir, typeName+defaults.FileExtension)
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create %s: %v", path, err)
	}
	defer f.Close()

	w := delimited.NewWriter(f)
	if err = w.PutProto(&types.Header{Type: typ, Created: 1, Version: "test"}); err != nil {
		t.Fatalf("write header: %v", err)
	}
	for _, r := range records {
		if err = w.PutProto(r); err != nil {
			t.Fatalf("write record: %v", err)
		}
	}

	return path
}

func dnsRecord(ts int64, src, dst string) proto.Message {
	return &types.DNS{Timestamp: ts, SrcIP: src, DstIP: dst}
}

func connRecord(first, last int64, src, dst string) proto.Message {
	return &types.Connection{TimestampFirst: first, TimestampLast: last, SrcIP: src, DstIP: dst}
}

// waitForTimelineIndex blocks until the background build finishes.
func waitForTimelineIndex(t *testing.T, dir string) *timelineIndex {
	t.Helper()

	deadline := time.Now().Add(20 * time.Second)

	for time.Now().Before(deadline) {
		status := timelineIndexFor(dir)

		switch status.State {
		case timelineStateReady:
			if status.Index == nil {
				t.Fatal("ready index is nil")
			}

			return status.Index
		case timelineStateError:
			t.Fatalf("index build failed: %s", status.Err)
		}

		time.Sleep(10 * time.Millisecond)
	}

	t.Fatal("timed out waiting for timeline index")

	return nil
}

func TestTimelineIndexOrdersRecordsChronologically(t *testing.T) {
	dir := t.TempDir()

	// Deliberately out of file order, with a duplicate timestamp and an
	// unusable timestamp that must not become an event.
	writeTimelineAuditFile(t, dir, "DNS", types.Type_NC_DNS, []proto.Message{
		dnsRecord(300, "10.0.0.3", "1.1.1.1"),
		dnsRecord(100, "10.0.0.1", "1.1.1.1"),
		dnsRecord(0, "10.0.0.9", "1.1.1.1"),
		dnsRecord(200, "10.0.0.2", "1.1.1.1"),
		dnsRecord(200, "10.0.0.4", "1.1.1.1"),
	})

	idx := waitForTimelineIndex(t, dir)

	track := idx.typeIndex("DNS")
	if track == nil {
		t.Fatal("DNS track missing")
	}

	if got, want := len(track.Events), 4; got != want {
		t.Fatalf("indexed events = %d, want %d", got, want)
	}

	if track.Invalid != 1 {
		t.Fatalf("invalid records = %d, want 1", track.Invalid)
	}

	if track.Total != 5 {
		t.Fatalf("total records = %d, want 5", track.Total)
	}

	wantTimes := []int64{100, 200, 200, 300}
	for i, want := range wantTimes {
		if track.Events[i].Time != want {
			t.Fatalf("event %d time = %d, want %d", i, track.Events[i].Time, want)
		}
	}

	// Equal timestamps keep file order via the ordinal.
	if track.Events[1].Ordinal >= track.Events[2].Ordinal {
		t.Fatalf("equal timestamps not ordered by ordinal: %d, %d", track.Events[1].Ordinal, track.Events[2].Ordinal)
	}

	if idx.MinTime != 100 || idx.MaxTime != 300 {
		t.Fatalf("bounds = [%d, %d], want [100, 300]", idx.MinTime, idx.MaxTime)
	}
}

func TestTimelineIndexNanosecondPrecision(t *testing.T) {
	dir := t.TempDir()

	base := int64(1_700_000_000_000_000_000)

	writeTimelineAuditFile(t, dir, "DNS", types.Type_NC_DNS, []proto.Message{
		dnsRecord(base+2, "10.0.0.1", "1.1.1.1"),
		dnsRecord(base+1, "10.0.0.2", "1.1.1.1"),
	})

	idx := waitForTimelineIndex(t, dir)
	track := idx.typeIndex("DNS")

	if track.Events[0].Time != base+1 || track.Events[1].Time != base+2 {
		t.Fatalf("nanosecond ordering lost: %v", track.Events)
	}
}

func TestTimelineSupportsUncompressedAuditFiles(t *testing.T) {
	dir := t.TempDir()

	writeTimelineAuditFilePlain(t, dir, "DNS", types.Type_NC_DNS, []proto.Message{
		dnsRecord(100, "10.0.0.1", "1.1.1.1"),
	})

	idx := waitForTimelineIndex(t, dir)
	if idx.TotalEvents != 1 || idx.typeIndex("DNS") == nil {
		t.Fatalf("uncompressed index = %+v, want one DNS event", idx)
	}

	s := newTimelineTestServer(dir)
	rec := httptest.NewRecorder()
	s.handleTimelineRecord(rec, httptest.NewRequest(http.MethodGet, "/api/timeline/record?type=DNS&ordinal=0&time=100", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("uncompressed record status = %d: %s", rec.Code, rec.Body.String())
	}
}

func TestTimelineIndexDetectsDurations(t *testing.T) {
	dir := t.TempDir()

	writeTimelineAuditFile(t, dir, "DNS", types.Type_NC_DNS, []proto.Message{
		dnsRecord(100, "10.0.0.1", "1.1.1.1"),
	})
	writeTimelineAuditFile(t, dir, "Connection", types.Type_NC_Connection, []proto.Message{
		connRecord(50, 400, "10.0.0.1", "10.0.0.2"),
		connRecord(120, 120, "10.0.0.3", "10.0.0.4"), // zero length: no bar
	})

	idx := waitForTimelineIndex(t, dir)

	if dns := idx.typeIndex("DNS"); dns.hasDuration() {
		t.Fatal("DNS must not be a duration track")
	}

	conn := idx.typeIndex("Connection")
	if !conn.hasDuration() {
		t.Fatal("Connection must be a duration track")
	}

	if conn.Ends[0] != 400 {
		t.Fatalf("end = %d, want 400", conn.Ends[0])
	}

	if conn.Ends[1] != 0 {
		t.Fatalf("degenerate interval kept an end: %d", conn.Ends[1])
	}

	if conn.MaxDuration != 350 {
		t.Fatalf("max duration = %d, want 350", conn.MaxDuration)
	}
}

func TestTimelinePaginationCoversEveryRecordOnce(t *testing.T) {
	dir := t.TempDir()

	var dnsRecords, ethRecords []proto.Message

	for i := range 40 {
		dnsRecords = append(dnsRecords, dnsRecord(int64(100+i*10), "10.0.0.1", "1.1.1.1"))
		ethRecords = append(ethRecords, &types.Ethernet{Timestamp: int64(105 + i*10), SrcMAC: "aa", DstMAC: "bb"})
	}

	writeTimelineAuditFile(t, dir, "DNS", types.Type_NC_DNS, dnsRecords)
	writeTimelineAuditFile(t, dir, "Ethernet", types.Type_NC_Ethernet, ethRecords)

	idx := waitForTimelineIndex(t, dir)

	base := timelineQuery{Start: idx.MinTime, End: idx.MaxTime, Tracks: idx.Types, Limit: 7}

	if got, want := base.count(), int64(80); got != want {
		t.Fatalf("count = %d, want %d", got, want)
	}

	var (
		seen  []tlKey
		query = base
	)

	for range 100 {
		hits := query.page()
		if len(hits) == 0 {
			break
		}

		for _, hit := range hits {
			seen = append(seen, query.key(hit.Track, hit.Index))
		}

		last := hits[len(hits)-1]
		next := base
		next.After = ptrKey(query.key(last.Track, last.Index))
		query = next
	}

	if len(seen) != 80 {
		t.Fatalf("paged %d records, want 80", len(seen))
	}

	unique := make(map[tlKey]bool, len(seen))

	for i, key := range seen {
		if unique[key] {
			t.Fatalf("duplicate record at position %d: %+v", i, key)
		}

		unique[key] = true

		if i > 0 && !seen[i-1].less(key) {
			t.Fatalf("pagination out of order at %d: %+v then %+v", i, seen[i-1], key)
		}
	}
}

func TestTimelineBackwardPaginationMirrorsForward(t *testing.T) {
	dir := t.TempDir()

	var records []proto.Message
	for i := range 25 {
		records = append(records, dnsRecord(int64(100+i), "10.0.0.1", "1.1.1.1"))
	}

	writeTimelineAuditFile(t, dir, "DNS", types.Type_NC_DNS, records)

	idx := waitForTimelineIndex(t, dir)

	forward := timelineQuery{Start: idx.MinTime, End: idx.MaxTime, Tracks: idx.Types, Limit: 25}
	all := forward.page()

	if len(all) != 25 {
		t.Fatalf("forward page = %d, want 25", len(all))
	}

	// The page preceding the 20th record must be records 15..19.
	cursor := forward.key(all[19].Track, all[19].Index)

	backward := timelineQuery{Start: idx.MinTime, End: idx.MaxTime, Tracks: idx.Types, Limit: 5, Before: &cursor}
	prev := backward.page()

	if len(prev) != 5 {
		t.Fatalf("backward page = %d, want 5", len(prev))
	}

	for i := range prev {
		want := forward.key(all[14+i].Track, all[14+i].Index)
		got := backward.key(prev[i].Track, prev[i].Index)

		if got != want {
			t.Fatalf("backward item %d = %+v, want %+v", i, got, want)
		}
	}
}

func TestTimelineWindowAndFilters(t *testing.T) {
	dir := t.TempDir()

	writeTimelineAuditFile(t, dir, "DNS", types.Type_NC_DNS, []proto.Message{
		dnsRecord(100, "10.0.0.1", "1.1.1.1"),
		dnsRecord(500, "10.0.0.2", "8.8.8.8"),
		dnsRecord(900, "10.0.0.3", "1.1.1.1"),
	})
	writeTimelineAuditFile(t, dir, "Connection", types.Type_NC_Connection, []proto.Message{
		connRecord(10, 600, "10.0.0.9", "10.0.0.8"), // starts before the window, overlaps it
		connRecord(950, 990, "10.0.0.7", "10.0.0.6"),
	})

	idx := waitForTimelineIndex(t, dir)

	window := timelineQuery{Start: 400, End: 600, Tracks: idx.Types, Limit: 50}

	hits := window.page()
	if len(hits) != 2 {
		t.Fatalf("window hits = %d, want 2 (one DNS, one overlapping connection)", len(hits))
	}

	if window.count() != 2 {
		t.Fatalf("window count = %d, want 2", window.count())
	}

	if hits[0].Track.Name != "Connection" {
		t.Fatalf("overlapping connection missing, got %s first", hits[0].Track.Name)
	}

	// Track filter.
	onlyDNS := timelineQuery{Start: idx.MinTime, End: idx.MaxTime, Tracks: timelineTracksFor(idx, "DNS"), Limit: 50}
	if got := onlyDNS.count(); got != 3 {
		t.Fatalf("DNS-only count = %d, want 3", got)
	}

	// Endpoint search.
	search := timelineQuery{Start: idx.MinTime, End: idx.MaxTime, Tracks: idx.Types, Search: "8.8.8.8", Limit: 50}
	if got := search.count(); got != 1 {
		t.Fatalf("search count = %d, want 1", got)
	}
}

func TestTimelineNearestUsesSelectedTrackAndSearch(t *testing.T) {
	dir := t.TempDir()

	writeTimelineAuditFile(t, dir, "DNS", types.Type_NC_DNS, []proto.Message{
		dnsRecord(100, "10.0.0.1", "1.1.1.1"),
		dnsRecord(500, "10.0.0.2", "8.8.8.8"),
		dnsRecord(900, "10.0.0.3", "9.9.9.9"),
	})

	idx := waitForTimelineIndex(t, dir)
	query := timelineQuery{Start: idx.MinTime, End: idx.MaxTime, Tracks: idx.Types, Limit: 1}

	hit := query.nearest(480)
	if hit == nil || hit.Track.Events[hit.Index].Time != 500 {
		t.Fatalf("nearest event = %+v, want timestamp 500", hit)
	}

	query.Search = "9.9.9.9"
	hit = query.nearest(480)
	if hit == nil || hit.Track.Events[hit.Index].Time != 900 {
		t.Fatalf("filtered nearest event = %+v, want timestamp 900", hit)
	}
}

func TestTimelineBucketsSpanDurations(t *testing.T) {
	dir := t.TempDir()

	writeTimelineAuditFile(t, dir, "DNS", types.Type_NC_DNS, []proto.Message{
		dnsRecord(100, "10.0.0.1", "1.1.1.1"),
	})
	writeTimelineAuditFile(t, dir, "Connection", types.Type_NC_Connection, []proto.Message{
		connRecord(100, 1000, "10.0.0.1", "10.0.0.2"),
	})

	idx := waitForTimelineIndex(t, dir)

	query := timelineQuery{Start: 100, End: 1100, Tracks: idx.Types, Limit: 50}
	buckets, matchCount := query.buckets(10)
	if matchCount != 2 {
		t.Fatalf("bucket match count = %d, want 2", matchCount)
	}

	dns := buckets["DNS"]
	if dns[0] != 1 {
		t.Fatalf("DNS first bucket = %d, want 1", dns[0])
	}

	var dnsTotal int64
	for _, c := range dns {
		dnsTotal += c
	}

	if dnsTotal != 1 {
		t.Fatalf("point record spans %d buckets, want 1", dnsTotal)
	}

	conn := buckets["Connection"]

	var filled int
	for _, c := range conn {
		if c > 0 {
			filled++
		}
	}

	if filled != 10 {
		t.Fatalf("connection spans %d buckets, want 10", filled)
	}
}

func TestTimelineIndexInvalidatedOnNewRecords(t *testing.T) {
	dir := t.TempDir()

	writeTimelineAuditFile(t, dir, "DNS", types.Type_NC_DNS, []proto.Message{
		dnsRecord(100, "10.0.0.1", "1.1.1.1"),
	})

	first := waitForTimelineIndex(t, dir)
	if got := first.TotalEvents; got != 1 {
		t.Fatalf("initial events = %d, want 1", got)
	}

	// Rewrite with more records; the fingerprint must change and rebuild.
	time.Sleep(10 * time.Millisecond)
	writeTimelineAuditFile(t, dir, "DNS", types.Type_NC_DNS, []proto.Message{
		dnsRecord(100, "10.0.0.1", "1.1.1.1"),
		dnsRecord(200, "10.0.0.2", "1.1.1.1"),
	})

	second := waitForTimelineIndex(t, dir)

	if second.Generation == first.Generation {
		t.Fatal("generation did not change after rewriting audit records")
	}

	if got := second.TotalEvents; got != 2 {
		t.Fatalf("rebuilt events = %d, want 2", got)
	}
}

func TestTimelineCursorRoundTrip(t *testing.T) {
	key := tlKey{Time: 1_700_000_000_000_000_123, LayerRank: 3, Type: "DNS", Ordinal: 42}

	decoded, err := decodeTimelineCursor(key.encode())
	if err != nil {
		t.Fatalf("decode: %v", err)
	}

	if *decoded != key {
		t.Fatalf("round trip = %+v, want %+v", *decoded, key)
	}

	if _, err = decodeTimelineCursor("not-a-cursor"); err == nil {
		t.Fatal("malformed cursor accepted")
	}
}

// newTimelineTestServer wires a Server with a fixed output directory.
func newTimelineTestServer(outDir string) *Server {
	return &Server{outDir: outDir, baseOutDir: outDir}
}

func TestTimelineHandlersServeRecords(t *testing.T) {
	dir := t.TempDir()

	writeTimelineAuditFile(t, dir, "DNS", types.Type_NC_DNS, []proto.Message{
		dnsRecord(100, "10.0.0.1", "1.1.1.1"),
		dnsRecord(200, "10.0.0.2", "8.8.8.8"),
	})

	waitForTimelineIndex(t, dir)

	s := newTimelineTestServer(dir)

	// meta
	rec := httptest.NewRecorder()
	s.handleTimelineMeta(rec, httptest.NewRequest(http.MethodGet, "/api/timeline/meta", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("meta status = %d", rec.Code)
	}

	var meta timelineMetaJSON
	if err := json.Unmarshal(rec.Body.Bytes(), &meta); err != nil {
		t.Fatalf("meta decode: %v", err)
	}

	if meta.Status != timelineStateReady || len(meta.Tracks) != 1 {
		t.Fatalf("unexpected meta: %+v", meta)
	}

	if meta.MinTime != "100" || meta.MaxTime != "200" {
		t.Fatalf("meta bounds = [%s, %s], want [100, 200]", meta.MinTime, meta.MaxTime)
	}

	// events
	rec = httptest.NewRecorder()
	s.handleTimelineEvents(rec, httptest.NewRequest(http.MethodGet, "/api/timeline/events?limit=1", nil))

	var events timelineEventsJSON
	if err := json.Unmarshal(rec.Body.Bytes(), &events); err != nil {
		t.Fatalf("events decode: %v", err)
	}

	if len(events.Events) != 1 || !events.HasMore || events.HasPrev {
		t.Fatalf("unexpected events page: %+v", events)
	}

	if events.Events[0].Time != "100" {
		t.Fatalf("first event time = %s, want 100", events.Events[0].Time)
	}

	// second page via cursor
	rec = httptest.NewRecorder()
	s.handleTimelineEvents(rec, httptest.NewRequest(http.MethodGet, "/api/timeline/events?limit=1&generation="+meta.Generation+"&after="+events.Events[0].Cursor, nil))

	var second timelineEventsJSON
	if err := json.Unmarshal(rec.Body.Bytes(), &second); err != nil {
		t.Fatalf("second page decode: %v", err)
	}

	if len(second.Events) != 1 || second.Events[0].Time != "200" {
		t.Fatalf("unexpected second page: %+v", second.Events)
	}

	if second.HasMore || !second.HasPrev {
		t.Fatalf("second page boundaries wrong: hasMore=%v hasPrev=%v", second.HasMore, second.HasPrev)
	}

	// full record detail
	ordinal := strconv.FormatInt(int64(second.Events[0].Ordinal), 10)

	rec = httptest.NewRecorder()
	s.handleTimelineRecord(rec, httptest.NewRequest(http.MethodGet, "/api/timeline/record?type=DNS&ordinal="+ordinal+"&time=200", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("record status = %d: %s", rec.Code, rec.Body.String())
	}

	var detail timelineRecordJSON
	if err := json.Unmarshal(rec.Body.Bytes(), &detail); err != nil {
		t.Fatalf("record decode: %v", err)
	}

	if detail.Time != "200" || detail.Src != "10.0.0.2" || detail.Dst != "8.8.8.8" {
		t.Fatalf("unexpected record detail: %+v", detail)
	}

	if len(detail.Record) == 0 {
		t.Fatal("record payload missing")
	}

	// buckets
	rec = httptest.NewRecorder()
	s.handleTimelineBuckets(rec, httptest.NewRequest(http.MethodGet, "/api/timeline/buckets?buckets=4", nil))

	var buckets timelineBucketsJSON
	if err := json.Unmarshal(rec.Body.Bytes(), &buckets); err != nil {
		t.Fatalf("buckets decode: %v", err)
	}

	if len(buckets.Series) != 1 || len(buckets.Series[0].Counts) != 4 || buckets.Series[0].Total != 2 {
		t.Fatalf("unexpected buckets: %+v", buckets.Series)
	}
}

func TestTimelineRecordRejectsPathTraversal(t *testing.T) {
	dir := t.TempDir()

	writeTimelineAuditFile(t, dir, "DNS", types.Type_NC_DNS, []proto.Message{
		dnsRecord(100, "10.0.0.1", "1.1.1.1"),
	})

	s := newTimelineTestServer(dir)

	rec := httptest.NewRecorder()
	s.handleTimelineRecord(rec, httptest.NewRequest(http.MethodGet, "/api/timeline/record?type=../../etc/passwd&ordinal=0", nil))

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("traversal status = %d, want 400", rec.Code)
	}
}

func TestTimelineRecordRejectsUnindexedOrdinal(t *testing.T) {
	dir := t.TempDir()

	writeTimelineAuditFile(t, dir, "DNS", types.Type_NC_DNS, []proto.Message{
		dnsRecord(100, "10.0.0.1", "1.1.1.1"),
	})
	waitForTimelineIndex(t, dir)

	s := newTimelineTestServer(dir)
	rec := httptest.NewRecorder()
	s.handleTimelineRecord(rec, httptest.NewRequest(http.MethodGet, "/api/timeline/record?type=DNS&ordinal=2147483647&time=100", nil))

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("unindexed ordinal status = %d, want 400", rec.Code)
	}
}

func TestTimelineQueryClampsExtremeBounds(t *testing.T) {
	idx := &timelineIndex{MinTime: 100, MaxTime: 200}
	req := httptest.NewRequest(http.MethodGet, "/api/timeline/events?start=-9223372036854775808&end=-9223372036854775808", nil)

	query, err := timelineQueryFromRequest(req, idx, timelineDefaultEventLimit, timelineMaxEventLimit)
	if err != nil {
		t.Fatalf("extreme bounds: %v", err)
	}
	if query.Start != 100 || query.End != 101 {
		t.Fatalf("clamped bounds = [%d,%d], want [100,101]", query.Start, query.End)
	}
}

func TestTimelineEventsRejectMalformedCursor(t *testing.T) {
	dir := t.TempDir()

	writeTimelineAuditFile(t, dir, "DNS", types.Type_NC_DNS, []proto.Message{
		dnsRecord(100, "10.0.0.1", "1.1.1.1"),
	})

	waitForTimelineIndex(t, dir)

	s := newTimelineTestServer(dir)

	rec := httptest.NewRecorder()
	s.handleTimelineEvents(rec, httptest.NewRequest(http.MethodGet, "/api/timeline/events?after=not-a-cursor", nil))

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("cursor status = %d, want 400", rec.Code)
	}
}

func TestTimelineEventsRejectAmbiguousPaginationAndStaleGeneration(t *testing.T) {
	dir := t.TempDir()

	writeTimelineAuditFile(t, dir, "DNS", types.Type_NC_DNS, []proto.Message{
		dnsRecord(100, "10.0.0.1", "1.1.1.1"),
	})

	idx := waitForTimelineIndex(t, dir)
	track := idx.typeIndex("DNS")
	cursor := tlKey{Time: 100, LayerRank: track.LayerRank, Type: "DNS", Ordinal: 0}.encode()
	s := newTimelineTestServer(dir)

	rec := httptest.NewRecorder()
	s.handleTimelineEvents(rec, httptest.NewRequest(http.MethodGet, "/api/timeline/events?after="+cursor+"&before="+cursor, nil))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("ambiguous pagination status = %d, want 400", rec.Code)
	}

	rec = httptest.NewRecorder()
	s.handleTimelineEvents(rec, httptest.NewRequest(http.MethodGet, "/api/timeline/events?after="+cursor, nil))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("generation-less cursor status = %d, want 400", rec.Code)
	}

	rec = httptest.NewRecorder()
	s.handleTimelineEvents(rec, httptest.NewRequest(http.MethodGet, "/api/timeline/events?generation=stale", nil))
	if rec.Code != http.StatusConflict {
		t.Fatalf("stale generation status = %d, want 409", rec.Code)
	}
}

func TestTimelineHandlersReportIndexingState(t *testing.T) {
	dir := t.TempDir()

	// No audit records at all: the index is trivially ready and empty.
	s := newTimelineTestServer(dir)

	rec := httptest.NewRecorder()
	s.handleTimelineMeta(rec, httptest.NewRequest(http.MethodGet, "/api/timeline/meta", nil))

	var meta timelineMetaJSON
	if err := json.Unmarshal(rec.Body.Bytes(), &meta); err != nil {
		t.Fatalf("meta decode: %v", err)
	}

	if meta.Status != timelineStateReady || len(meta.Tracks) != 0 || meta.TotalEvents != 0 {
		t.Fatalf("unexpected empty meta: %+v", meta)
	}
}

func TestTimelineCaptureBoundsIgnoreAbstractOutliers(t *testing.T) {
	dir := t.TempDir()

	writeTimelineAuditFile(t, dir, "DNS", types.Type_NC_DNS, []proto.Message{
		dnsRecord(100, "10.0.0.1", "1.1.1.1"),
		dnsRecord(200, "10.0.0.1", "1.1.1.1"),
	})
	writeTimelineAuditFile(t, dir, "Connection", types.Type_NC_Connection, []proto.Message{
		connRecord(100, 1_000_000, "10.0.0.1", "1.1.1.1"),
	})

	idx := waitForTimelineIndex(t, dir)
	if idx.MinTime != 100 || idx.MaxTime != 1_000_000 {
		t.Fatalf("all-event bounds = [%d,%d], want [100,1000000]", idx.MinTime, idx.MaxTime)
	}
	if idx.CaptureMin != 100 || idx.CaptureMax != 200 {
		t.Fatalf("capture bounds = [%d,%d], want [100,200]", idx.CaptureMin, idx.CaptureMax)
	}
}

func TestTimelineHandlersScopeRequestsByInputFile(t *testing.T) {
	dirA := t.TempDir()
	dirB := t.TempDir()
	inputA := filepath.Join(t.TempDir(), "a.pcap")
	inputB := filepath.Join(t.TempDir(), "b.pcap")

	writeTimelineAuditFile(t, dirA, "DNS", types.Type_NC_DNS, []proto.Message{
		dnsRecord(100, "10.0.0.1", "1.1.1.1"),
	})
	writeTimelineAuditFile(t, dirB, "DNS", types.Type_NC_DNS, []proto.Message{
		dnsRecord(900, "10.0.0.2", "8.8.8.8"),
		dnsRecord(1000, "10.0.0.3", "9.9.9.9"),
	})
	waitForTimelineIndex(t, dirA)
	waitForTimelineIndex(t, dirB)

	s := &Server{
		outDir: dirA,
		fileOutputDirs: map[string]string{
			inputA: dirA,
			inputB: dirB,
		},
	}

	load := func(input string) timelineMetaJSON {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/api/timeline/meta?inputFile="+url.QueryEscape(input), nil)
		s.handleTimelineMeta(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("meta status for %s = %d: %s", input, rec.Code, rec.Body.String())
		}

		var meta timelineMetaJSON
		if err := json.Unmarshal(rec.Body.Bytes(), &meta); err != nil {
			t.Fatalf("decode meta for %s: %v", input, err)
		}
		return meta
	}

	metaA := load(inputA)
	metaB := load(inputB)

	if metaA.MinTime != "100" || metaA.TotalEvents != 1 {
		t.Fatalf("capture A meta = %+v", metaA)
	}
	if metaB.MinTime != "900" || metaB.MaxTime != "1000" || metaB.TotalEvents != 2 {
		t.Fatalf("capture B meta = %+v", metaB)
	}
	if metaA.Generation == metaB.Generation {
		t.Fatal("different PCAP outputs received the same timeline generation")
	}
}
