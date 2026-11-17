package webui

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/dreadl0ck/netcap/types"
	"github.com/gogo/protobuf/proto"
)

func TestCanceledAuditStatsDoesNotPublishCounts(t *testing.T) {
	dir := t.TempDir()
	writeTimelineAuditFilePlain(t, dir, "HTTP", types.Type_NC_HTTP, []proto.Message{&types.HTTP{Method: "GET"}})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if stats := getAuditStatsForDirectory(ctx, dir); stats.TotalRecords != 0 {
		t.Fatal("canceled scan counted records", stats)
	}
	w := httptest.NewRecorder()
	HandleAuditStats(dir)(w, httptest.NewRequest("GET", "/api/audit-stats", nil).WithContext(ctx))
	if w.Body.Len() != 0 {
		t.Fatal("canceled scan published an audit total", w.Body.String())
	}
}

func TestAuditMetaReportsIncompleteFrameCount(t *testing.T) {
	file := writeTimelineAuditFilePlain(t, t.TempDir(), "HTTP", types.Type_NC_HTTP, []proto.Message{&types.HTTP{Method: "GET"}})
	for _, complete := range []bool{true, false} {
		if !complete {
			f, err := os.OpenFile(file, os.O_WRONLY|os.O_APPEND, 0)
			if err != nil {
				t.Fatal(err)
			}
			_, writeErr := f.Write([]byte{4})
			if err := f.Close(); err != nil || writeErr != nil {
				t.Fatal(err, writeErr)
			}
		}
		w := httptest.NewRecorder()
		HandleAuditMeta(w, httptest.NewRequest("GET", "/", nil), file, "HTTP")
		var result struct {
			RecordCount         int64
			RecordCountComplete bool
		}
		if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil || result.RecordCount != 1 || result.RecordCountComplete != complete {
			t.Fatal(result, err)
		}
	}
}

func TestInventoryAndRecordQueryPreferSameAuditEncoding(t *testing.T) {
	dir := t.TempDir()
	rows := []proto.Message{&types.HTTP{Method: "GET"}, &types.HTTP{Method: "POST"}}
	writeTimelineAuditFilePlain(t, dir, "HTTP", types.Type_NC_HTTP, rows)
	for _, want := range []int64{2, 1} {
		if want == 1 {
			writeTimelineAuditFile(t, dir, "HTTP", types.Type_NC_HTTP, rows[:1])
		}
		files, err := ListAuditFiles(dir)
		if err != nil || len(files) != 1 || files[0].RecordCount != want {
			t.Fatal(files, err)
		}
		if stats := getAuditStatsForDirectory(context.Background(), dir); stats.TotalRecords != want {
			t.Fatal(stats)
		}
		w := httptest.NewRecorder()
		HandleAuditRecords(dir)(w, httptest.NewRequest("GET", "/api/audit/HTTP/meta", nil))
		var meta struct{ RecordCount int64 }
		if err := json.Unmarshal(w.Body.Bytes(), &meta); err != nil || w.Code != 200 || meta.RecordCount != want {
			t.Fatal(w.Code, w.Body.String(), err)
		}
	}
}

func TestAuditCountsAreIndependentOfPageLimits(t *testing.T) {
	rows := make([]proto.Message, 1200)
	for i := range rows {
		port := "80"
		if i%2 == 0 {
			port = "443"
		}
		rows[i] = &types.Connection{SrcIP: "192.0.2.1", SrcPort: port}
	}
	file := writeTimelineAuditFile(t, t.TempDir(), "Connection", types.Type_NC_Connection, rows)
	for _, tc := range []struct {
		query           string
		total, returned int
	}{
		{"countOnly=true&limit=1&offset=9999", 1200, 0},
		{"countOnly=true&limit=500&filter=" + url.QueryEscape("SrcPort == '443'"), 600, 0},
		{"limit=5&offset=599&filter=" + url.QueryEscape("SrcPort == '443'"), 600, 1},
		{"limit=2&offset=9999", 1200, 0},
		{"limit=2&offset=1", 1200, 2},
	} {
		w := httptest.NewRecorder()
		HandleAuditStream(w, httptest.NewRequest("GET", "/?"+tc.query, nil), file, "Connection")
		body := w.Body.String()
		if strings.Contains(body, "event: error") {
			t.Fatal(body)
		}
		parts := strings.Split(body, "event: complete\ndata: ")
		if len(parts) != 2 {
			t.Fatal("missing completion event", body)
		}
		var summary struct{ Total, Scanned, Count int }
		if err := json.Unmarshal([]byte(strings.TrimSpace(parts[1])), &summary); err != nil {
			t.Fatal(err)
		}
		if summary.Total != tc.total || summary.Scanned != 1200 || summary.Count != tc.returned || strings.Count(body, "event: record\n") != tc.returned {
			t.Fatalf("%s: %+v", tc.query, summary)
		}
	}
}
