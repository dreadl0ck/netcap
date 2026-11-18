/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 */

package webui

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
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

func TestSmallTimelineCompletesWhileRegularLaneIsOccupied(t *testing.T) {
	timelineBuildSlot <- struct{}{}
	defer func() { <-timelineBuildSlot }()
	for name, write := range map[string]func(*testing.T, string, string, types.Type, []proto.Message) string{
		"plain": writeTimelineAuditFilePlain, "compressed": writeTimelineAuditFile,
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			write(t, dir, "Connection", types.Type_NC_Connection, []proto.Message{
				connRecord(100, 200, "192.0.2.1", "192.0.2.2"),
				connRecord(300, 400, "192.0.2.2", "192.0.2.1"),
			})
			started := time.Now()
			index := waitForTimelineIndex(t, dir)
			t.Logf("time to ready while regular lane held: %v", time.Since(started))
			if track := index.byName["Connection"]; track == nil || len(track.Events) != 2 {
				t.Fatal("reserved timeline lane lost records")
			}
		})
	}
}

func TestDeletingCaptureCancelsQueuedTimeline(t *testing.T) {
	timelineSmallBuildSlot <- struct{}{}
	defer func() { <-timelineSmallBuildSlot }()
	dir := t.TempDir()
	writeTimelineAuditFilePlain(t, dir, "Connection", types.Type_NC_Connection, []proto.Message{connRecord(1, 2, "192.0.2.1", "192.0.2.2")})
	status := timelineIndexFor(dir)
	if status.State != timelineStateIndexing || status.finished == nil {
		t.Fatalf("expected a queued timeline: %+v", status)
	}
	clearOwnedAnalysisCaches(dir)
	select {
	case <-status.finished:
	case <-time.After(2 * time.Second):
		t.Fatal("deleted capture kept waiting for an occupied timeline slot")
	}
	if len(timelineSmallBuildSlot) != 1 {
		t.Fatal("canceled build released another job's slot")
	}
}

func TestSmallTimelineDuringLargeIndexBuild(t *testing.T) {
	large, small := t.TempDir(), t.TempDir()
	records := make([]proto.Message, 150_000)
	for i := range records {
		records[i] = connRecord(int64(i+1), int64(i+2), "192.0.2.1", "192.0.2.2")
	}
	writeTimelineAuditFilePlain(t, large, "Connection", types.Type_NC_Connection, records)
	writeTimelineAuditFilePlain(t, small, "Connection", types.Type_NC_Connection, records[:2])
	started := time.Now()
	largeStatus := timelineIndexFor(large)
	if largeStatus.finished == nil {
		t.Fatalf("large build not scheduled: %s", largeStatus.State)
	}
	smallStarted := time.Now()
	smallStatus := timelineIndexFor(small)
	if smallStatus.State == timelineStateIndexing {
		select {
		case <-smallStatus.finished:
		case <-time.After(10 * time.Second):
			t.Fatal("small build did not finish")
		}
	}
	smallElapsed := time.Since(smallStarted)
	smallIndex := waitForTimelineIndex(t, small)
	largePending := true
	select {
	case <-largeStatus.finished:
		largePending = false
	default:
	}
	largeIndex := waitForTimelineIndex(t, large)
	if smallIndex.TotalEvents != 2 || largeIndex.TotalEvents != int64(len(records)) || largeIndex.Truncated || smallIndex.Truncated {
		t.Fatalf("unexpected indexes: small=%d large=%d", smallIndex.TotalEvents, largeIndex.TotalEvents)
	}
	t.Logf("two-event ready in %s; 150000-event build still pending at small readiness: %t; both ready in %s", smallElapsed, largePending, time.Since(started))
}

func TestSmallTimelineReportsCorruptInputWhileRegularLaneIsOccupied(t *testing.T) {
	timelineBuildSlot <- struct{}{}
	defer func() { <-timelineBuildSlot }()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "Connection.ncap.gz"), []byte("invalid gzip data"), 0600); err != nil {
		t.Fatal(err)
	}
	status := timelineIndexFor(dir)
	select {
	case <-status.finished:
	case <-time.After(2 * time.Second):
		t.Fatal("small corrupt input waited for the regular lane")
	}
	if status := timelineIndexFor(dir); status.State != timelineStateError || !strings.Contains(status.Err, "index Connection: gzip: invalid header") {
		t.Fatalf("unexpected timeline status: %+v", status)
	}
}

func TestTimelineDiscoveryCountsNonAuditEntries(t *testing.T) {
	dir := t.TempDir()
	writeTimelineAuditFilePlain(t, dir, "HTTP", types.Type_NC_HTTP, []proto.Message{&types.HTTP{Timestamp: 1}})
	baseline, _, err := timelineFingerprint(dir)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < maxTimelineDirectoryEntries-1; i++ {
		if err := os.WriteFile(filepath.Join(dir, "ignored-"+strconv.Itoa(i)), nil, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if got, files, err := timelineFingerprint(dir); err != nil || got != baseline || len(files) != 1 {
		t.Fatalf("at limit: generation=%q files=%d err=%v", got, len(files), err)
	}
	if err := os.Mkdir(filepath.Join(dir, "one-more"), 0700); err != nil {
		t.Fatal(err)
	}
	if got, files, err := timelineFingerprint(dir); err == nil || got != "" || len(files) != 0 {
		t.Fatalf("over limit: generation=%q files=%d err=%v", got, len(files), err)
	}
}

func TestTimelineRejectsLinkedTrackBeforeIndexing(t *testing.T) {
	path := writeTimelineAuditFilePlain(t, t.TempDir(), "DNS", types.Type_NC_DNS, []proto.Message{dnsRecord(100, "192.0.2.1", "192.0.2.2")})
	dir := t.TempDir()
	if err := os.Symlink(path, filepath.Join(dir, "DNS.ncap")); err != nil {
		t.Fatal(err)
	}
	if status := timelineIndexFor(dir); status.State != timelineStateError || status.Index != nil || !strings.Contains(status.Err, "DNS.ncap is not a regular file") {
		t.Fatalf("linked track admitted: %+v", status)
	}
}

func TestTimelineRejectsLinkedReplacementAfterDiscovery(t *testing.T) {
	for _, regular := range []bool{false, true} {
		dir := t.TempDir()
		path := writeTimelineAuditFilePlain(t, dir, "DNS", types.Type_NC_DNS, []proto.Message{dnsRecord(100, "192.0.2.1", "192.0.2.2")})
		generation, files, err := timelineFingerprint(dir)
		if err != nil || len(files) != 1 {
			t.Fatalf("discover fixture: %v, %v", files, err)
		}
		if regular {
			files[0].size = timelineSmallInputBytes + 1
		}
		moved := filepath.Join(t.TempDir(), "DNS.ncap")
		if err := os.Rename(path, moved); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(moved, path); err != nil {
			t.Fatal(err)
		}
		entry := &timelineIndexEntry{finished: make(chan struct{}), state: timelineStateIndexing}
		buildTimelineIndex(entry, dir, generation, files)
		if entry.state != timelineStateError || entry.index != nil || entry.errMsg != "index DNS: invalid artifact path" {
			t.Fatalf("regular lane=%t: replacement not rejected on open: %s %s", regular, entry.state, entry.errMsg)
		}
	}
}

func TestTimelineRejectsSameMetadataReplacementAfterDiscovery(t *testing.T) {
	for _, regular := range []bool{false, true} {
		dir := t.TempDir()
		path := writeTimelineAuditFilePlain(t, dir, "HTTP", types.Type_NC_HTTP, []proto.Message{&types.HTTP{Timestamp: 100, Method: "GET"}})
		generation, files, err := timelineFingerprint(dir)
		if err != nil || len(files) != 1 {
			t.Fatalf("discover fixture: %v, %v", files, err)
		}
		if regular {
			files[0].size = timelineSmallInputBytes + 1
		}
		replacement := writeTimelineAuditFilePlain(t, t.TempDir(), "HTTP", types.Type_NC_HTTP, []proto.Message{&types.HTTP{Timestamp: 101, Method: "PUT"}})
		mtime := files[0].info.ModTime()
		if err := os.Chtimes(replacement, mtime, mtime); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(replacement, path); err != nil {
			t.Fatal(err)
		}
		if current, _, err := timelineFingerprint(dir); err != nil || current != generation {
			t.Fatalf("replacement must preserve the metadata fingerprint: %q %v", current, err)
		}
		entry := &timelineIndexEntry{finished: make(chan struct{}), state: timelineStateIndexing}
		buildTimelineIndex(entry, dir, generation, files)
		if entry.state != timelineStateError || entry.index != nil || entry.errMsg != "index HTTP: timeline input changed" {
			t.Fatalf("regular lane=%t: %s %s", regular, entry.state, entry.errMsg)
		}
	}
}

func TestTimelineBuildBoundsCommunityMetadata(t *testing.T) {
	dir := t.TempDir()
	rows := []proto.Message{
		&types.Software{Timestamp: 100, CommunityIDs: []string{"one", "two"}},
		&types.Software{Timestamp: 200, CommunityIDs: []string{"one", "two"}},
	}
	writeTimelineAuditFilePlain(t, dir, "Software", types.Type_NC_Software, rows)
	_, files, err := timelineFingerprint(dir)
	if err != nil || len(files) != 1 {
		t.Fatalf("discover fixture: %v", err)
	}
	const exact = 2*(64+3) + 2*(64+8) // Two unique strings and two extra ID lists.
	index, err := indexTimelineType(files[0], 10, exact, nil)
	if err != nil || len(index.Events) != 2 || len(index.strings) != 2 || len(index.extraCIDs) != 2 {
		t.Fatalf("exact-fit metadata lost repeated IDs: %v", err)
	}
	if index, err := indexTimelineType(files[0], 10, exact-1, nil); index != nil || err != errTimelineMetadataBudget {
		t.Fatalf("metadata budget returned an index or wrong error: %v", err)
	}
}

func TestTimelineBuildEnforcesAuditFrameLimit(t *testing.T) {
	for _, extra := range []int{0, 1} {
		dir := t.TempDir()
		frame := &types.HTTP{Timestamp: 100, RequestBody: make([]byte, timelineMaxAuditFrameBytes)}
		frame.RequestBody = frame.RequestBody[:timelineMaxAuditFrameBytes+extra-(proto.Size(frame)-len(frame.RequestBody))]
		if proto.Size(frame) != timelineMaxAuditFrameBytes+extra {
			t.Fatal("unexpected fixture frame size")
		}
		writeTimelineAuditFilePlain(t, dir, "HTTP", types.Type_NC_HTTP, []proto.Message{frame})
		fingerprint, files, err := timelineFingerprint(dir)
		if err != nil || len(files) != 1 {
			t.Fatalf("discover fixture: %v", err)
		}
		entry := &timelineIndexEntry{finished: make(chan struct{}), state: timelineStateIndexing}
		buildTimelineIndex(entry, dir, fingerprint, files)
		if extra == 0 {
			if entry.state != timelineStateReady || entry.index == nil || entry.index.TotalEvents != 1 {
				t.Fatalf("exact-limit frame: %s %s", entry.state, entry.errMsg)
			}
		} else if entry.state != timelineStateError || entry.index != nil || !strings.Contains(entry.errMsg, "record size exceeds read limit") {
			t.Fatalf("oversized frame: %s %s", entry.state, entry.errMsg)
		}
	}
}

func TestTimelineRejectsGenerationChangedBeforeBuild(t *testing.T) {
	dir := t.TempDir()
	writeTimelineAuditFilePlain(t, dir, "DNS", types.Type_NC_DNS, []proto.Message{dnsRecord(100, "192.0.2.1", "192.0.2.2")})
	generation, files, err := timelineFingerprint(dir)
	if err != nil {
		t.Fatal(err)
	}
	writeTimelineAuditFilePlain(t, dir, "UDP", types.Type_NC_UDP, []proto.Message{&types.UDP{Timestamp: 200}})
	entry := &timelineIndexEntry{finished: make(chan struct{}), state: timelineStateIndexing}
	buildTimelineIndex(entry, dir, generation, files)
	if entry.state != timelineStateError || entry.index != nil || entry.errMsg != "timeline input changed during indexing" {
		t.Fatalf("stale generation published: %s %s", entry.state, entry.errMsg)
	}
	index := waitForTimelineIndex(t, dir)
	if index.Generation == generation || index.byName["DNS"] == nil || index.byName["UDP"] == nil {
		t.Fatal("retry did not index the current generation")
	}
}

func TestTimelineOverExpansionReturnsCompleteRegularIndex(t *testing.T) {
	dir := t.TempDir()
	records := make([]proto.Message, 4096)
	for i := range records {
		records[i] = connRecord(int64(i+1), int64(i+2), strings.Repeat("x", 128), "192.0.2.2")
	}
	writeTimelineAuditFile(t, dir, "Connection", types.Type_NC_Connection, records)
	_, files, err := timelineFingerprint(dir)
	if err != nil || len(files) != 1 || files[0].size > timelineSmallInputBytes {
		t.Fatalf("fixture must fit the compressed admission cap: %v %v", files, err)
	}
	if snapshot, err := snapshotSmallTimeline(files, nil); snapshot != nil || err != nil {
		t.Fatalf("oversize snapshot should use the regular lane; error=%v", err)
	}
	index := waitForTimelineIndex(t, dir)
	if track := index.byName["Connection"]; index.Truncated || track == nil || len(track.Events) != len(records) {
		t.Fatal("regular lane did not index the entire expanded input")
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
	if err := os.WriteFile(filepath.Join(dir, "DNS.ncap.gz"), nil, 0600); err != nil {
		t.Fatal(err)
	}

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

func TestTimelineCacheRejectsReplacedAuditGeneration(t *testing.T) {
	dir := t.TempDir()
	path := writeTimelineAuditFilePlain(t, dir, "DNS", types.Type_NC_DNS, []proto.Message{dnsRecord(100, "192.0.2.1", "192.0.2.2")})
	fingerprint, files, err := timelineFingerprint(dir)
	if err != nil || len(files) != 1 {
		t.Fatalf("discover fixture: %v, %v", files, err)
	}
	first := waitForTimelineIndex(t, dir)
	replacement := writeTimelineAuditFilePlain(t, t.TempDir(), "DNS", types.Type_NC_DNS, []proto.Message{dnsRecord(101, "192.0.2.1", "192.0.2.2")})
	mtime := files[0].info.ModTime()
	if err := os.Chtimes(replacement, mtime, mtime); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(replacement, path); err != nil {
		t.Fatal(err)
	}
	if got, _, err := timelineFingerprint(dir); err != nil || got != fingerprint {
		t.Fatalf("replacement changed metadata fingerprint: %q, %v", got, err)
	}
	s := newTimelineTestServer(dir)
	w := httptest.NewRecorder()
	s.handleTimelineEvents(w, httptest.NewRequest(http.MethodGet, "/api/timeline/events?generation="+first.Generation, nil))
	if w.Code != http.StatusConflict {
		t.Fatalf("old generation status=%d, want 409", w.Code)
	}
	second := waitForTimelineIndex(t, dir)
	track := second.typeIndex("DNS")
	if second.Generation == first.Generation || second.TotalEvents != 1 || track == nil || !track.hasEvent(101, 0) {
		t.Fatal("replacement audit did not receive a fresh timeline generation")
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

type timelineRecordAdmissionContext struct {
	context.Context
	beforeRead func()
}

func (c *timelineRecordAdmissionContext) Done() <-chan struct{} {
	if c.beforeRead != nil {
		c.beforeRead()
		c.beforeRead = nil
	}
	return c.Context.Done()
}

func TestTimelineRecordRejectsReplacementAfterIndexSelection(t *testing.T) {
	dir := t.TempDir()
	path := writeTimelineAuditFilePlain(t, dir, "HTTP", types.Type_NC_HTTP, []proto.Message{&types.HTTP{Timestamp: 100, Method: "GET"}})
	idx := waitForTimelineIndex(t, dir)
	s := newTimelineTestServer(dir)
	replacement := writeTimelineAuditFilePlain(t, t.TempDir(), "HTTP", types.Type_NC_HTTP, []proto.Message{&types.HTTP{Timestamp: 100, Method: "PUT"}})
	ctx := &timelineRecordAdmissionContext{Context: t.Context(), beforeRead: func() {
		if err := os.Rename(replacement, path); err != nil {
			t.Fatal(err)
		}
	}}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/timeline/record?type=HTTP&ordinal=0&time=100&generation="+idx.Generation, nil)
	s.handleTimelineRecord(w, r.WithContext(ctx))
	if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "indexed audit file unavailable") {
		t.Fatalf("replacement record: status=%d body=%s", w.Code, w.Body)
	}
}

func TestTimelineEventAndBucketQueriesShareSlotsThroughWrite(t *testing.T) {
	dir := t.TempDir()
	writeTimelineAuditFilePlain(t, dir, "HTTP", types.Type_NC_HTTP, []proto.Message{
		&types.HTTP{Timestamp: 100, Method: "GET"},
		&types.HTTP{Timestamp: 200, Method: "GET"},
	})
	waitForTimelineIndex(t, dir)
	s := newTimelineTestServer(dir)
	release := make(chan struct{})
	defer func() {
		if release != nil {
			close(release)
		}
	}()
	done := make(chan int, cap(timelineQuerySlots))
	for range cap(timelineQuerySlots) {
		w := heldAlertPageResponse{httptest.NewRecorder(), make(chan struct{}, 1), release}
		go func() {
			s.handleTimelineEvents(w, httptest.NewRequest(http.MethodGet, "/api/timeline/events", nil))
			done <- w.Code
		}()
		select {
		case <-w.writing:
		case <-time.After(5 * time.Second):
			t.Fatal("event query did not begin writing")
		}
	}
	buckets := func() *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		s.handleTimelineBuckets(w, httptest.NewRequest(http.MethodGet, "/api/timeline/buckets", nil))
		return w
	}
	if w := buckets(); w.Code != http.StatusTooManyRequests || !strings.Contains(w.Body.String(), `"series":[]`) {
		t.Fatalf("saturated bucket query: %d %s", w.Code, w.Body)
	}
	close(release)
	release = nil
	for range cap(timelineQuerySlots) {
		select {
		case code := <-done:
			if code != http.StatusOK {
				t.Fatalf("event query status=%d", code)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("event query did not finish")
		}
	}
	if w := buckets(); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"matchCount":2`) {
		t.Fatalf("bucket query retry: %d %s", w.Code, w.Body)
	}
}

func TestTimelineRecordRejectsSaturationAndRecovers(t *testing.T) {
	dir := t.TempDir()
	writeTimelineAuditFilePlain(t, dir, "HTTP", types.Type_NC_HTTP, []proto.Message{&types.HTTP{Timestamp: 100, Method: "GET"}})
	idx := waitForTimelineIndex(t, dir)
	s := newTimelineTestServer(dir)
	path := "/api/timeline/record?type=HTTP&ordinal=0&time=100&generation=" + idx.Generation
	func() {
		for range cap(timelineRecordReadSlots) {
			timelineRecordReadSlots <- struct{}{}
			defer func() { <-timelineRecordReadSlots }()
		}
		ctx, cancel := context.WithTimeout(t.Context(), time.Second)
		defer cancel()
		w := httptest.NewRecorder()
		s.handleTimelineRecord(w, httptest.NewRequest(http.MethodGet, path, nil).WithContext(ctx))
		if w.Code != http.StatusTooManyRequests {
			t.Fatalf("saturated read: status=%d body=%s", w.Code, w.Body)
		}
	}()
	w := httptest.NewRecorder()
	s.handleTimelineRecord(w, httptest.NewRequest(http.MethodGet, path, nil))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"Method":"GET"`) {
		t.Fatalf("retry: status=%d body=%s", w.Code, w.Body)
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
