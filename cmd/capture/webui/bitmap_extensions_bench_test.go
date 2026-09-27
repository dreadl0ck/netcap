package webui

import (
	"compress/gzip"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/dreadl0ck/netcap/internal/delimited"
	"github.com/dreadl0ck/netcap/types"
)

func benchmarkCertificatesFile(b *testing.B) string {
	b.Helper()
	path := filepath.Join(b.TempDir(), "TLSCertificate.ncap.gz")
	f, err := os.Create(path)
	if err != nil {
		b.Fatal(err)
	}
	gz := gzip.NewWriter(f)
	w := delimited.NewWriter(gz)
	if err := w.PutProto(&types.Header{Type: types.Type_NC_TLSCertificate}); err != nil {
		b.Fatal(err)
	}
	for i := range 10_000 {
		if err := w.PutProto(&types.TLSCertificate{
			SHA256Fingerprint: fmt.Sprintf("sha-%d", i%500),
			CommunityID:       fmt.Sprintf("id-%d", i%200),
		}); err != nil {
			b.Fatal(err)
		}
	}
	if err := gz.Close(); err != nil {
		b.Fatal(err)
	}
	if err := f.Close(); err != nil {
		b.Fatal(err)
	}
	return filepath.Dir(path)
}

func BenchmarkCertificateCount(b *testing.B) {
	dir := benchmarkCertificatesFile(b)
	selected := map[string]bool{"id-1": true, "id-2": true}
	b.ResetTimer()
	for range b.N {
		if CountUniqueCertificatesWithCommunityIDFilter(dir, selected) < 1 {
			b.Fatal("missing certificates")
		}
	}
}

func BenchmarkCertificateScanCount(b *testing.B) {
	dir := benchmarkCertificatesFile(b)
	selected := map[string]bool{"id-1": true, "id-2": true}
	b.ResetTimer()
	for range b.N {
		rows, err := readCertificates(dir)
		if err != nil {
			b.Fatal(err)
		}
		var count int
		for _, row := range rows {
			if containsAnyCommunityIDBool(row.CommunityIDs, selected) {
				count++
			}
		}
		if count < 1 {
			b.Fatal("missing certificates")
		}
	}
}

func benchmarkTimelineTrack() *tlTypeIndex {
	const n = 100_000
	t := &tlTypeIndex{Name: "DNS", Events: make([]tlEvent, n), strings: []string{"10.0.0.1", "10.0.0.2"}}
	for i := range t.Events {
		t.Events[i] = tlEvent{Time: int64(i + 1), Ordinal: int32(i), Src: int32(i % 2), Dst: -1}
	}
	return t
}

func BenchmarkTimelineSubstringHostCount(b *testing.B) {
	t := benchmarkTimelineTrack()
	q := &timelineQuery{Start: 1, End: 100_000, Tracks: []*tlTypeIndex{t}, Search: "10.0.0.1"}
	b.ResetTimer()
	for range b.N {
		if got := q.count(); got != 50_000 {
			b.Fatalf("count = %d", got)
		}
	}
}

func BenchmarkTimelineHostFacetCount(b *testing.B) {
	t := benchmarkTimelineTrack()
	q := &timelineQuery{Start: 1, End: 100_000, Tracks: []*tlTypeIndex{t}, Host: "10.0.0.1"}
	t.buildFacets()
	b.ResetTimer()
	for range b.N {
		if got := q.count(); got != 50_000 {
			b.Fatalf("count = %d", got)
		}
	}
}

func BenchmarkTimelineHostFacetCold(b *testing.B) {
	b.ReportAllocs()
	for range b.N {
		b.StopTimer()
		t := benchmarkTimelineTrack()
		q := &timelineQuery{Start: 1, End: 100_000, Tracks: []*tlTypeIndex{t}, Host: "10.0.0.1"}
		b.StartTimer()
		if got := q.count(); got != 50_000 {
			b.Fatalf("count = %d", got)
		}
	}
}

func BenchmarkTimelineCommunityFacetCount(b *testing.B) {
	t := benchmarkTimelineTrack()
	t.strings = append(t.strings, "cid-one", "cid-other")
	t.cids = make([]int32, len(t.Events))
	for i := range t.cids {
		t.cids[i] = 3
		if i%1000 == 0 {
			t.cids[i] = 2
		}
	}
	q := &timelineQuery{Start: 1, End: 100_000, Tracks: []*tlTypeIndex{t}, CommunityIDs: map[string]bool{"cid-one": true}}
	t.buildFacets()
	b.ResetTimer()
	for range b.N {
		if got := q.count(); got != 100 {
			b.Fatalf("count = %d", got)
		}
	}
}

func BenchmarkTimelineCommunityScanCount(b *testing.B) {
	t := benchmarkTimelineTrack()
	t.strings = append(t.strings, "cid-one", "cid-other")
	t.cids = make([]int32, len(t.Events))
	for i := range t.cids {
		t.cids[i] = 3
		if i%1000 == 0 {
			t.cids[i] = 2
		}
	}
	q := &timelineQuery{Start: 1, End: 100_000, Tracks: []*tlTypeIndex{t}, CommunityIDs: map[string]bool{"cid-one": true}}
	b.ResetTimer()
	for range b.N {
		count := 0
		for i := range t.Events {
			if q.match(t, i) {
				count++
			}
		}
		if count != 100 {
			b.Fatalf("count = %d", count)
		}
	}
}
