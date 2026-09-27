package webui

import (
	"reflect"
	"sync"
	"testing"

	"github.com/gogo/protobuf/proto"

	"github.com/dreadl0ck/netcap/types"
)

func TestCertificateIndexDeduplicatesAllCommunityIDs(t *testing.T) {
	dir := t.TempDir()
	writeTimelineAuditFile(t, dir, "TLSCertificate", types.Type_NC_TLSCertificate, []proto.Message{
		&types.TLSCertificate{SHA256Fingerprint: "same", CommunityID: "one", Timestamp: 1},
		&types.TLSCertificate{SHA256Fingerprint: "same", CommunityID: "two", Timestamp: 2},
		&types.TLSCertificate{SHA256Fingerprint: "same", CommunityID: "two", Timestamp: 3},
		&types.TLSCertificate{SHA256Fingerprint: "other", CommunityID: "two", Timestamp: 4},
		&types.TLSCertificate{SerialNumber: "serial", IssuerCommonName: "issuer", CommunityID: "three"},
	})
	s, err := certificateSnapshotFor(dir)
	if err != nil || len(s.rows) != 3 || s.byID == nil {
		t.Fatalf("snapshot = (%+v, %v)", s, err)
	}
	for _, tt := range []struct {
		ids  map[string]bool
		want int64
	}{
		{map[string]bool{"one": true}, 1},
		{map[string]bool{"two": true}, 2},
		{map[string]bool{"one": true, "two": true}, 2},
		{map[string]bool{"three": true}, 1},
		{map[string]bool{"unknown": true}, 0},
	} {
		if got := CountUniqueCertificatesWithCommunityIDFilter(dir, tt.ids); got != tt.want {
			t.Errorf("IDs %v: got %d, want %d", tt.ids, got, tt.want)
		}
	}
	for _, row := range s.rows {
		if row.SHA256Fingerprint == "same" {
			if row.CommunityID != "one" || row.SeenCount != 3 || !reflect.DeepEqual(row.CommunityIDs, []string{"one", "two"}) {
				t.Fatalf("deduplicated certificate = %+v", row)
			}
		}
	}
	if got := cachedCertificateRows(dir); len(got) != 3 || CountUniqueCertificates(dir) != 3 {
		t.Fatalf("chart and menu counts = %d, %d", len(got), CountUniqueCertificates(dir))
	}
}

func TestCertificateIndexInvalidatesAndSharesBuild(t *testing.T) {
	dir := t.TempDir()
	writeTimelineAuditFile(t, dir, "TLSCertificate", types.Type_NC_TLSCertificate, []proto.Message{
		&types.TLSCertificate{SHA256Fingerprint: "first", CommunityID: "old"},
	})
	results := make([]*certificateSnapshot, 12)
	var wg sync.WaitGroup
	for i := range results {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			var err error
			results[i], err = certificateSnapshotFor(dir)
			if err != nil {
				t.Errorf("snapshot: %v", err)
			}
		}(i)
	}
	wg.Wait()
	for _, s := range results {
		if s == nil || s != results[0] {
			t.Fatal("concurrent builds were not shared")
		}
	}
	writeTimelineAuditFile(t, dir, "TLSCertificate", types.Type_NC_TLSCertificate, []proto.Message{
		&types.TLSCertificate{SHA256Fingerprint: "second", CommunityID: "new"},
		&types.TLSCertificate{SHA256Fingerprint: "second", CommunityID: "new"},
	})
	newSnapshot, err := certificateSnapshotFor(dir)
	if err != nil || newSnapshot == results[0] || newSnapshot.count(map[string]bool{"old": true}) != 0 || newSnapshot.count(map[string]bool{"new": true}) != 1 {
		t.Fatalf("stale snapshot: %+v, %v", newSnapshot, err)
	}
}

func TestCertificateIndexFallbackCountsUniqueRows(t *testing.T) {
	rows := make([]CertificateSummary, certificateMaxRows+1)
	for i := range rows {
		rows[i].CommunityIDs = []string{"one", "two"}
	}
	s := newCertificateSnapshot(rows)
	if s.byID != nil || s.count(map[string]bool{"one": true, "two": true}) != int64(len(rows)) {
		t.Fatal("fallback must count deduplicated rows exactly once")
	}
}
