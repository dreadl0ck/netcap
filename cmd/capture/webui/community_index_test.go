package webui

import (
	"compress/gzip"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/gogo/protobuf/proto"

	"github.com/dreadl0ck/netcap/internal/delimited"
	"github.com/dreadl0ck/netcap/types"
)

func TestCommunityCountsAndFilteredFiles(t *testing.T) {
	dir := t.TempDir()
	path := writeTimelineAuditFile(t, dir, "DNS", types.Type_NC_DNS, []proto.Message{
		&types.DNS{CommunityID: "one"}, &types.DNS{CommunityID: "two"},
		&types.DNS{CommunityID: "one"}, &types.DNS{},
	})
	writeTimelineAuditFile(t, dir, "Host", types.Type_NC_Host, []proto.Message{&types.Host{}})

	for _, tc := range []struct {
		ids  map[string]bool
		want int64
	}{
		{map[string]bool{"one": true}, 2},
		{map[string]bool{"one": true, "two": true, "missing": true}, 3},
		{map[string]bool{"missing": true}, 0},
	} {
		total, matched, err := communityCounts(path, tc.ids)
		if err != nil || total != 4 || matched != tc.want {
			t.Fatalf("communityCounts(%v) = (%d, %d, %v), want (4, %d)", tc.ids, total, matched, err, tc.want)
		}
	}

	files, err := ListAuditFilesWithCommunityIDFilter(dir, map[string]bool{"one": true, "two": true})
	if err != nil || len(files) != 2 {
		t.Fatalf("filtered files = (%v, %v)", files, err)
	}
	for _, f := range files {
		switch f.Type {
		case "DNS":
			if f.RecordCount != 4 || f.FilteredCount != 3 {
				t.Fatalf("DNS counts = %+v", f)
			}
		case "Host":
			if f.RecordCount != 1 || f.FilteredCount != 0 {
				t.Fatalf("Host counts = %+v", f)
			}
		default:
			t.Fatalf("unexpected file %+v", f)
		}
	}
	if CountRecordsWithCommunityIDFilter(path, map[string]bool{"one": true}) != 2 {
		t.Fatal("filtered menu count disagrees with file list")
	}
}

func TestCommunityIndexInvalidatesOnRewrite(t *testing.T) {
	dir := t.TempDir()
	path := writeTimelineAuditFile(t, dir, "DNS", types.Type_NC_DNS, []proto.Message{&types.DNS{CommunityID: "old"}})
	ids := map[string]bool{"old": true}
	if _, matched, err := communityCounts(path, ids); err != nil || matched != 1 {
		t.Fatalf("initial counts = (%d, %v)", matched, err)
	}
	writeTimelineAuditFile(t, dir, "DNS", types.Type_NC_DNS, []proto.Message{
		&types.DNS{CommunityID: "new"}, &types.DNS{CommunityID: "new"},
	})
	if total, matched, err := communityCounts(path, ids); err != nil || total != 2 || matched != 0 {
		t.Fatalf("stale counts = (%d, %d, %v)", total, matched, err)
	}
	if _, matched, err := communityCounts(path, map[string]bool{"new": true}); err != nil || matched != 2 {
		t.Fatalf("new counts = (%d, %v)", matched, err)
	}
}

func TestUnfilteredCountReusesOnlyCurrentCompletedIndex(t *testing.T) {
	dir := t.TempDir()
	path := writeTimelineAuditFile(t, dir, "DNS", types.Type_NC_DNS, []proto.Message{
		&types.DNS{CommunityID: "first"},
	})
	if _, ok := communityCachedTotal(path); ok {
		t.Fatal("unfiltered count should not trigger an index build")
	}
	if got := CountRecords(path); got != 1 {
		t.Fatalf("cold count = %d", got)
	}
	if _, ok := communityCachedTotal(path); ok {
		t.Fatal("count-only scan unexpectedly built an index")
	}
	if _, _, err := communityCounts(path, map[string]bool{"first": true}); err != nil {
		t.Fatal(err)
	}
	if got, ok := communityCachedTotal(path); !ok || got != 1 {
		t.Fatalf("cached total = %d, %v", got, ok)
	}
	writeTimelineAuditFile(t, dir, "DNS", types.Type_NC_DNS, []proto.Message{
		&types.DNS{CommunityID: "second"}, &types.DNS{CommunityID: "second"},
	})
	if _, ok := communityCachedTotal(path); ok {
		t.Fatal("stale count survived a file rewrite")
	}
	if got := CountRecords(path); got != 2 {
		t.Fatalf("rewritten count = %d", got)
	}
}

func TestCommunityIndexRepeatedIDsCountEachRecordOnce(t *testing.T) {
	dir := t.TempDir()
	files := []struct {
		name string
		typ  types.Type
		rows []proto.Message
	}{
		{"Software", types.Type_NC_Software, []proto.Message{
			&types.Software{CommunityIDs: []string{"one", "two", "one"}},
			&types.Software{CommunityIDs: []string{"two"}},
			&types.Software{},
		}},
		{"Vulnerability", types.Type_NC_Vulnerability, []proto.Message{
			&types.Vulnerability{CommunityIDs: []string{"one", "two"}},
		}},
		{"Exploit", types.Type_NC_Exploit, []proto.Message{
			&types.Exploit{CommunityIDs: []string{"two"}},
		}},
	}
	for _, file := range files {
		path := writeTimelineAuditFile(t, dir, file.name, file.typ, file.rows)
		for _, ids := range []map[string]bool{{"one": true, "two": true}, {"two": true}} {
			total, matched, err := communityCounts(path, ids)
			_, scanMatched, scanErr := scanCommunityCounts(path, ids)
			want := int64(1)
			if file.name == "Software" {
				want = 2
			}
			if err != nil || scanErr != nil || total != int64(len(file.rows)) || matched != want || scanMatched != want {
				t.Fatalf("%s %v: indexed (%d, %d, %v), scan (%d, %v), want %d", file.name, ids, total, matched, err, scanMatched, scanErr, want)
			}
		}
	}
}

func TestCommunityIndexFallsBackWhenTooManyIDs(t *testing.T) {
	dir := t.TempDir()
	records := make([]proto.Message, communityIndexMaxIDs+1)
	for i := range records {
		records[i] = &types.DNS{CommunityID: fmt.Sprintf("id-%d", i)}
	}
	path := writeTimelineAuditFile(t, dir, "DNS", types.Type_NC_DNS, records)
	total, matched, err := communityCounts(path, map[string]bool{"id-0": true, "id-4096": true})
	if err != nil || total != int64(len(records)) || matched != 2 {
		t.Fatalf("fallback counts = (%d, %d, %v)", total, matched, err)
	}
	communityIndexCache.Lock()
	entry, cached := communityIndexCache.files[path]
	communityIndexCache.Unlock()
	if !cached || entry.index != nil {
		t.Fatal("oversized file must have a scan-only cache entry")
	}
	if total, matched, err := communityCounts(path, map[string]bool{"id-4096": true}); err != nil || total != int64(len(records)) || matched != 1 {
		t.Fatalf("repeat fallback counts = (%d, %d, %v)", total, matched, err)
	}
}

func TestCommunityCountsConcurrentRequests(t *testing.T) {
	dir := t.TempDir()
	path := writeTimelineAuditFile(t, dir, "DNS", types.Type_NC_DNS, []proto.Message{
		&types.DNS{CommunityID: "one"}, &types.DNS{CommunityID: "two"},
	})
	var wg sync.WaitGroup
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if total, matched, err := communityCounts(path, map[string]bool{"one": true}); err != nil || total != 2 || matched != 1 {
				t.Errorf("counts = (%d, %d, %v)", total, matched, err)
			}
		}()
	}
	wg.Wait()
	if _, matched, err := communityCounts(filepath.Join(dir, "missing.ncap.gz"), map[string]bool{"one": true}); err != nil || matched != 0 {
		t.Fatalf("missing file = (%d, %v)", matched, err)
	}
}

func BenchmarkCommunityCounts(b *testing.B) {
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
		if err := w.PutProto(&types.DNS{CommunityID: fmt.Sprintf("id-%d", i%100)}); err != nil {
			b.Fatal(err)
		}
	}
	if err := gz.Close(); err != nil {
		b.Fatal(err)
	}
	if err := f.Close(); err != nil {
		b.Fatal(err)
	}
	ids := map[string]bool{"id-1": true, "id-2": true}
	if _, _, err := communityCounts(path, ids); err != nil {
		b.Fatal(err)
	}
	b.Run("scan", func(b *testing.B) {
		for range b.N {
			if _, _, err := scanCommunityCounts(path, ids); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("indexed", func(b *testing.B) {
		for range b.N {
			if _, _, err := communityCounts(path, ids); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("unfiltered-scan", func(b *testing.B) {
		for range b.N {
			if total, _, err := scanCommunityCounts(path, nil); err != nil || total != 10_000 {
				b.Fatalf("scan count = %d, %v", total, err)
			}
		}
	})
	b.Run("unfiltered-cached", func(b *testing.B) {
		for range b.N {
			if got := CountRecords(path); got != 10_000 {
				b.Fatalf("cached count = %d", got)
			}
		}
	})
}
