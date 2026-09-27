package webui

import (
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/gogo/protobuf/proto"

	"github.com/dreadl0ck/netcap/types"
)

func TestTimelineExactFacetsAcrossQueries(t *testing.T) {
	dir := t.TempDir()
	writeTimelineAuditFile(t, dir, "DNS", types.Type_NC_DNS, []proto.Message{
		&types.DNS{Timestamp: 100, SrcIP: "10.0.0.1", DstIP: "8.8.8.8", CommunityID: "one"},
		&types.DNS{Timestamp: 200, SrcIP: "10.0.0.2", DstIP: "8.8.8.8", CommunityID: "two"},
		&types.DNS{Timestamp: 300, SrcIP: "10.0.0.1", DstIP: "8.8.8.8", CommunityID: "two"},
	})
	writeTimelineAuditFile(t, dir, "Software", types.Type_NC_Software, []proto.Message{
		&types.Software{Timestamp: 150, CommunityIDs: []string{"one", "two"}},
	})
	idx := waitForTimelineIndex(t, dir)
	q, err := timelineQueryFromRequest(httptest.NewRequest("GET", "/api/timeline/events?communityId=two&limit=1", nil), idx, 100, 500)
	if err != nil {
		t.Fatal(err)
	}
	if got := q.count(); got != 3 {
		t.Fatalf("filtered count = %d, want 3", got)
	}
	first := q.page()
	if len(first) != 1 || first[0].Track.Name != "Software" {
		t.Fatalf("first page = %+v", first)
	}
	q.After = ptrKey(q.key(first[0].Track, first[0].Index))
	second := q.page()
	if len(second) != 1 || second[0].Track.Name != "DNS" || second[0].Track.Events[second[0].Index].Time != 200 {
		t.Fatalf("second page = %+v", second)
	}
	q.After = nil
	q.Before = ptrKey(q.key(second[0].Track, second[0].Index))
	if backward := q.page(); len(backward) != 1 || backward[0].Track.Name != "Software" {
		t.Fatalf("backward page = %+v", backward)
	}
	q.Before = nil
	if hit := q.nearest(160); hit == nil || hit.Track.Name != "Software" {
		t.Fatalf("nearest = %+v", hit)
	}
	_, count := q.buckets(8)
	if count != 3 {
		t.Fatalf("bucket count = %d, want 3", count)
	}

	q.Search = "dns"
	if got := q.count(); got != 2 {
		t.Fatalf("substring AND facets = %d, want 2", got)
	}
	q.Search = ""
	q.Host = "10.0.0.1"
	if got := q.count(); got != 1 {
		t.Fatalf("exact host AND community ID = %d, want 1", got)
	}
	q.Host = "10.0.0.10"
	if got := q.count(); got != 0 {
		t.Fatalf("exact host accidentally matched substring: %d", got)
	}
	q.Host = ""
	q.CommunityIDs = map[string]bool{"one": true, "two": true}
	if got := q.count(); got != 4 {
		t.Fatalf("multi-ID union double-counted an event: %d", got)
	}
}

func TestTimelineFacetFallbackMatchesUnindexedQuery(t *testing.T) {
	track := benchmarkTimelineTrack()
	track.strings = append(track.strings, "cid")
	track.cids = make([]int32, len(track.Events))
	for i := range track.cids {
		track.cids[i] = -1
		if i%500 == 0 {
			track.cids[i] = 2
		}
	}
	q := &timelineQuery{Start: 1, End: 100_000, Tracks: []*tlTypeIndex{track}, Host: "10.0.0.1", CommunityIDs: map[string]bool{"cid": true}, Limit: 5}
	want := q.count()
	wantHits := q.page()
	if want != 200 || len(wantHits) != 5 || track.hosts == nil {
		t.Fatalf("indexed query = %d, %+v", want, wantHits)
	}
	track.hosts, track.community = nil, nil
	if got, hits := q.count(), q.page(); got != want || !reflect.DeepEqual(hits, wantHits) {
		t.Fatalf("fallback = %d %+v; indexed = %d %+v", got, hits, want, wantHits)
	}
}

func TestTimelineFacetIndexPreservesIDsAfterTimeSort(t *testing.T) {
	dir := t.TempDir()
	writeTimelineAuditFile(t, dir, "DNS", types.Type_NC_DNS, []proto.Message{
		&types.DNS{Timestamp: 300, CommunityID: "late", SrcIP: "10.0.0.3"},
		&types.DNS{Timestamp: 100, CommunityID: "early", SrcIP: "10.0.0.1"},
		&types.DNS{Timestamp: 200, CommunityID: "middle", SrcIP: "10.0.0.2"},
	})
	idx := waitForTimelineIndex(t, dir)
	for _, tc := range []struct {
		id   string
		time int64
	}{
		{"early", 100}, {"middle", 200}, {"late", 300},
	} {
		q := &timelineQuery{Start: 100, End: 300, Tracks: idx.Types, CommunityIDs: map[string]bool{tc.id: true}, Limit: 10}
		page := q.page()
		if len(page) != 1 || page[0].Track.Events[page[0].Index].Time != tc.time {
			t.Fatalf("%s after sort = %+v, want time %d", tc.id, page, tc.time)
		}
	}
	writeTimelineAuditFile(t, dir, "DNS", types.Type_NC_DNS, []proto.Message{
		&types.DNS{Timestamp: 400, CommunityID: "new", SrcIP: "10.0.0.4"},
	})
	updated := waitForTimelineIndex(t, dir)
	if updated == idx {
		t.Fatal("timeline index generation did not change")
	}
	q := &timelineQuery{Start: 400, End: 401, Tracks: updated.Types, CommunityIDs: map[string]bool{"late": true}, Limit: 10}
	if got := q.count(); got != 0 {
		t.Fatalf("stale Community ID after rewrite: %d", got)
	}
	q.CommunityIDs = map[string]bool{"new": true}
	if got := q.count(); got != 1 {
		t.Fatalf("new Community ID after rewrite: %d", got)
	}
}

func TestTimelineFacetBudgetFallsBackToExactScan(t *testing.T) {
	track := benchmarkTimelineTrack()
	idx := &timelineIndex{facetBytes: timelineFacetMaxBytes}
	track.owner = idx
	q := &timelineQuery{Start: 1, End: 100_000, Tracks: []*tlTypeIndex{track}, Host: "10.0.0.1", Limit: 4}
	if got := q.count(); got != 50_000 || track.hosts != nil || len(q.page()) != 4 {
		t.Fatalf("budget fallback = %d hits, indexed %v", got, track.hosts != nil)
	}
}
