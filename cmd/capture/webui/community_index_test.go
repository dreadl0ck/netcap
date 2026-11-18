package webui

import (
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
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

func TestCommunityIndexBuildAdmissionKeepsCacheHitsAvailable(t *testing.T) {
	rows := []proto.Message{&types.DNS{CommunityID: "fixture"}}
	warm := writeTimelineAuditFilePlain(t, t.TempDir(), "DNS", types.Type_NC_DNS, rows)
	cold := writeTimelineAuditFilePlain(t, t.TempDir(), "DNS", types.Type_NC_DNS, rows)
	if idx, err := communityIndexFor(warm); err != nil || idx == nil {
		t.Fatalf("prime index: %v, %v", idx, err)
	}
	func() {
		for range cap(communityIndexBuildSlots) {
			communityIndexBuildSlots <- struct{}{}
			defer func() { <-communityIndexBuildSlots }()
		}
		if idx, err := communityIndexFor(cold); idx != nil || !errors.Is(err, errCommunityIndexBusy) {
			t.Fatalf("cold index at saturation: %v, %v", idx, err)
		}
		w := httptest.NewRecorder()
		HandleAuditFilesFiltered(filepath.Dir(cold))(w, httptest.NewRequest(http.MethodGet, "/api/files/audit/filtered?communityIds=fixture", nil))
		if w.Code != http.StatusTooManyRequests {
			t.Fatalf("filtered inventory at saturation: %d, %s", w.Code, w.Body.String())
		}
		if idx, err := communityIndexFor(warm); err != nil || idx == nil || idx.total != 1 {
			t.Fatalf("cache hit at saturation: %v, %v", idx, err)
		}
	}()
	if idx, err := communityIndexFor(cold); err != nil || idx == nil || idx.total != 1 {
		t.Fatalf("cold index retry: %v, %v", idx, err)
	}
}

func TestCommunityIndexWaitHonorsRequestDeadline(t *testing.T) {
	path := writeTimelineAuditFilePlain(t, t.TempDir(), "DNS", types.Type_NC_DNS, []proto.Message{&types.DNS{CommunityID: "fixture"}})
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	entry := &communityIndexEntry{info: info, ready: make(chan struct{})}
	communityIndexCache.Lock()
	communityIndexCache.files[path] = entry
	communityIndexCache.Unlock()
	t.Cleanup(func() {
		communityIndexCache.Lock()
		delete(communityIndexCache.files, path)
		close(entry.ready)
		communityIndexCache.Unlock()
	})
	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()
	result := make(chan error, 1)
	go func() {
		_, _, err := communityCountsContext(ctx, path, map[string]bool{"fixture": true})
		result <- err
	}()
	select {
	case err := <-result:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("waiting query returned %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("waiting query did not honor the deadline")
	}
	if total, matched, err := scanCommunityCountsContext(ctx, path, map[string]bool{"fixture": true}); total != 0 || matched != 0 || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("canceled fallback scan: total=%d matched=%d err=%v", total, matched, err)
	}
}

func TestCommunityIndexInvalidatesSameSizeReplacement(t *testing.T) {
	dir := t.TempDir()
	path := writeTimelineAuditFilePlain(t, dir, "DNS", types.Type_NC_DNS, []proto.Message{&types.DNS{CommunityID: "old"}})
	stamp := time.Unix(1700000000, 0)
	if err := os.Chtimes(path, stamp, stamp); err != nil {
		t.Fatal(err)
	}
	ids := map[string]bool{"old": true}
	if _, matched, err := communityCounts(path, ids); err != nil || matched != 1 {
		t.Fatalf("initial counts: %d, %v", matched, err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	replacement := writeTimelineAuditFilePlain(t, t.TempDir(), "DNS", types.Type_NC_DNS, []proto.Message{&types.DNS{CommunityID: "new"}})
	if err := os.Chtimes(replacement, info.ModTime(), info.ModTime()); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(replacement, path); err != nil {
		t.Fatal(err)
	}
	after, err := os.Stat(path)
	if err != nil || after.Size() != info.Size() || !after.ModTime().Equal(info.ModTime()) || os.SameFile(info, after) {
		t.Fatalf("replacement fixture did not preserve size and mtime while changing identity: %v", err)
	}
	if _, ok := communityCachedTotal(path); ok {
		t.Fatal("cached total survived a file replacement")
	}
	if idx, err := buildCommunityIndex(path, info); idx != nil || err != errCommunityAuditChanged {
		t.Fatalf("stale build snapshot accepted: index=%v, err=%v", idx, err)
	}
	if total, matched, err := communityCounts(path, ids); err != nil || total != 1 || matched != 0 {
		t.Fatalf("replacement counts: %d, %d, %v", total, matched, err)
	}
}

func TestCommunityIndexRejectsMismatchedHeader(t *testing.T) {
	path := writeTimelineAuditFilePlain(t, t.TempDir(), "DNS", types.Type_NC_UDP, []proto.Message{&types.UDP{SrcPort: 5353}})
	if total, matched, err := communityCounts(path, map[string]bool{"fixture": true}); err == nil || total != 0 || matched != 0 {
		t.Fatalf("mislabeled track: total=%d, matched=%d, err=%v", total, matched, err)
	}
	if _, ok := communityCachedTotal(path); ok {
		t.Fatal("mislabeled track populated the cache")
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

func TestCommunityIndexBoundsRecordMemberships(t *testing.T) {
	const records, width = 1000, 1000
	ids := make([]string, width)
	for i := range ids {
		ids[i] = fmt.Sprintf("id-%d", i)
	}
	rows := make([]proto.Message, records)
	for i := range rows {
		rows[i] = &types.Software{CommunityIDs: ids}
	}
	rows[records-1] = &types.Software{CommunityIDs: append(append([]string(nil), ids...), ids[0])}
	path := writeTimelineAuditFilePlain(t, t.TempDir(), "Software", types.Type_NC_Software, rows)
	if idx, err := communityIndexFor(path); err != nil || idx == nil || idx.total != records {
		t.Fatalf("exact-limit fixture: index present=%t err=%v", idx != nil, err)
	}
	rows = append(rows, &types.Software{CommunityIDs: []string{ids[0]}})
	path = writeTimelineAuditFilePlain(t, t.TempDir(), "Software", types.Type_NC_Software, rows)
	total, matched, err := communityCounts(path, map[string]bool{ids[0]: true})
	_, cached := communityCachedTotal(path)
	if err != nil || total != records+1 || matched != records+1 || cached {
		t.Fatalf("over-limit fallback: total=%d matched=%d cached=%t err=%v", total, matched, cached, err)
	}
}

func TestCommunityIndexFallsBackWhenKeysExceedByteBudget(t *testing.T) {
	for _, over := range []bool{false, true} {
		dir := t.TempDir()
		key := strings.Repeat("x", 1<<20)
		rows := []proto.Message{
			&types.DNS{CommunityID: key}, &types.DNS{CommunityID: "a" + key[1:]},
			&types.DNS{CommunityID: "b" + key[1:]}, &types.DNS{CommunityID: "c" + key[1:]},
			&types.DNS{CommunityID: key},
		}
		if over {
			rows = append(rows, &types.DNS{CommunityID: "extra"})
		}
		path := writeTimelineAuditFilePlain(t, dir, "DNS", types.Type_NC_DNS, rows)
		total, matched, err := communityCounts(path, map[string]bool{key: true})
		_, cached := communityCachedTotal(path)
		if err != nil || total != int64(len(rows)) || matched != 2 || cached == over {
			t.Fatalf("over=%t: total=%d matched=%d cached=%t err=%v", over, total, matched, cached, err)
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
