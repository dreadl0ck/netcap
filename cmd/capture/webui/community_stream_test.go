package webui

import (
	"compress/gzip"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gogo/protobuf/proto"

	"github.com/dreadl0ck/netcap/internal/delimited"
	"github.com/dreadl0ck/netcap/types"
)

func TestAuditStreamCommunityBitmapPreservesFilteringAndCounts(t *testing.T) {
	dir := t.TempDir()
	path := writeTimelineAuditFile(t, dir, "DNS", types.Type_NC_DNS, []proto.Message{
		&types.DNS{CommunityID: "one", SrcIP: "10.0.0.1"},
		&types.DNS{CommunityID: "two", SrcIP: "10.0.0.2"},
		&types.DNS{CommunityID: "two", SrcIP: "10.0.0.1"},
		&types.DNS{SrcIP: "10.0.0.1"},
	})
	stream := func(query string) string {
		t.Helper()
		rec := httptest.NewRecorder()
		HandleAuditStream(rec, httptest.NewRequest("GET", "/api/audit/DNS/stream?"+query, nil), path, "DNS")
		return rec.Body.String()
	}
	page := stream("communityId=one&communityId=two&offset=1&limit=1")
	if strings.Count(page, "event: record\n") != 1 || !strings.Contains(page, `"SrcIP":"10.0.0.2"`) || !strings.Contains(page, `"total": 1, "scanned": 4`) {
		t.Fatalf("multi-ID page = %s", page)
	}
	matched := stream("communityId=two&filter=SrcIP%20%3D%3D%20%2210.0.0.1%22")
	if strings.Count(matched, "event: record\n") != 1 || !strings.Contains(matched, `"total": 1, "scanned": 4`) || strings.Contains(matched, "event: error") {
		t.Fatalf("AND filter = %s", matched)
	}
	if got := stream("communityId=unknown"); strings.Contains(got, "event: record\n") || !strings.Contains(got, `"scanned": 4`) {
		t.Fatalf("unknown ID = %s", got)
	}
}

func TestAuditStreamCommunityFallbackAndRepeatedIDs(t *testing.T) {
	dir := t.TempDir()
	path := writeTimelineAuditFile(t, dir, "Software", types.Type_NC_Software, []proto.Message{
		&types.Software{CommunityIDs: []string{"one", "two"}}, &types.Software{CommunityIDs: []string{"three"}},
	})
	rec := httptest.NewRecorder()
	HandleAuditStream(rec, httptest.NewRequest("GET", "/api/audit/Software/stream?communityId=two", nil), path, "Software")
	if strings.Count(rec.Body.String(), "event: record\n") != 1 || !strings.Contains(rec.Body.String(), `"scanned": 2`) {
		t.Fatalf("repeated ID stream = %s", rec.Body.String())
	}
	rows := make([]proto.Message, communityIndexMaxIDs+1)
	for i := range rows {
		rows[i] = &types.Software{CommunityIDs: []string{fmt.Sprintf("id-%d", i)}}
	}
	path = writeTimelineAuditFile(t, dir, "Software", types.Type_NC_Software, rows)
	rec = httptest.NewRecorder()
	HandleAuditStream(rec, httptest.NewRequest("GET", "/api/audit/Software/stream?communityId=id-4096", nil), path, "Software")
	if strings.Count(rec.Body.String(), "event: record\n") != 1 || !strings.Contains(rec.Body.String(), `"scanned": 4097`) {
		t.Fatalf("oversized fallback = %s", rec.Body.String())
	}
}

func BenchmarkAuditStreamCommunitySelection(b *testing.B) {
	path := filepath.Join(b.TempDir(), "DNS.ncap.gz")
	f, err := os.Create(path)
	if err != nil {
		b.Fatal(err)
	}
	gz := gzip.NewWriter(f)
	w := delimited.NewWriter(gz)
	if err := w.PutProto(&types.Header{Type: types.Type_NC_DNS}); err != nil {
		b.Fatal(err)
	}
	for i := range 10_000 {
		if err := w.PutProto(&types.DNS{CommunityID: fmt.Sprintf("id-%d", i%100), SrcIP: "10.0.0.1"}); err != nil {
			b.Fatal(err)
		}
	}
	if err := gz.Close(); err != nil {
		b.Fatal(err)
	}
	if err := f.Close(); err != nil {
		b.Fatal(err)
	}
	if _, err := communityIndexFor(path); err != nil {
		b.Fatal(err)
	}
	for _, tc := range []struct{ name, query string }{
		{"expression-scan", "filter=CommunityID%20%3D%3D%20%22id-1%22&limit=10"},
		{"bitmap-prefilter", "communityId=id-1&limit=10"},
	} {
		b.Run(tc.name, func(b *testing.B) {
			for range b.N {
				rec := httptest.NewRecorder()
				HandleAuditStream(rec, httptest.NewRequest("GET", "/api/audit/DNS/stream?"+tc.query, nil), path, "DNS")
				if strings.Count(rec.Body.String(), "event: record\n") != 10 || strings.Contains(rec.Body.String(), "event: error") {
					b.Fatal("incomplete stream")
				}
			}
		})
	}
}
