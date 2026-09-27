package webui

import (
	"compress/gzip"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/gogo/protobuf/proto"

	"github.com/dreadl0ck/netcap/internal/delimited"
	"github.com/dreadl0ck/netcap/types"
)

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
				if len(cachedConnectionRows(dir)) != 10_000 {
					b.Fatal("incomplete chart data")
				}
			}
		}
	})
}
