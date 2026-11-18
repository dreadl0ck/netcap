package webui

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/types"
	"github.com/gogo/protobuf/proto"
)

type stalledAuditResponse struct {
	*httptest.ResponseRecorder
	net.Conn
	writeErr error
}

func (w *stalledAuditResponse) Write(p []byte) (int, error) {
	n, err := w.Conn.Write(p)
	w.writeErr = err
	return n, err
}

func TestFullAuditStreamDeadlineReleasesStalledWrite(t *testing.T) {
	file := writeTimelineAuditFilePlain(t, t.TempDir(), "HTTP", types.Type_NC_HTTP, []proto.Message{&types.HTTP{Method: "GET"}})
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 500*time.Millisecond)
	defer cancel()
	w := &stalledAuditResponse{ResponseRecorder: httptest.NewRecorder(), Conn: server}
	done := make(chan struct{})
	go func() {
		defer close(done)
		HandleAuditStream(w, httptest.NewRequest(http.MethodGet, "/stream?full=true", nil).WithContext(ctx), file, "HTTP")
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("stalled response did not release its stream slot")
	}
	if !errors.Is(w.writeErr, os.ErrDeadlineExceeded) {
		t.Fatalf("stalled write returned %v, want deadline exceeded", w.writeErr)
	}
}

func BenchmarkAuditRecordEventLarge(b *testing.B) {
	payload := []byte(`{"body":"` + strings.Repeat("x", 8<<20) + `"}`)
	b.Run("formatted", func(b *testing.B) {
		for b.Loop() {
			if _, err := fmt.Fprintf(io.Discard, "event: record\ndata: %s\n\n", payload); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("direct", func(b *testing.B) {
		for b.Loop() {
			if err := writeAuditRecordEvent(io.Discard, payload); err != nil {
				b.Fatal(err)
			}
		}
	})
}

func TestFullAuditStreamRefusesOversizedFrameBeforeReadingBody(t *testing.T) {
	path := writeTimelineAuditFilePlain(t, t.TempDir(), "HTTP", types.Type_NC_HTTP, nil)
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, writeErr := f.Write(binary.AppendUvarint(nil, maxFullAuditFrameBytes+1))
	if err := f.Close(); err != nil || writeErr != nil {
		t.Fatalf("write fixture: %v, %v", writeErr, err)
	}
	for _, query := range []string{"?full=true", "?full=true&countOnly=true"} {
		w := httptest.NewRecorder()
		HandleAuditStream(w, httptest.NewRequest(http.MethodGet, "/stream"+query, nil), path, "HTTP")
		body := w.Body.String()
		if !strings.Contains(body, "event: error") || !strings.Contains(body, "record size exceeds read limit") || strings.Contains(body, "event: complete") {
			t.Fatalf("%s: unexpected stream %q", query, body)
		}
	}
}

func TestFullAuditStreamEnforcesCumulativeScanBudget(t *testing.T) {
	frame := &types.HTTP{RequestBody: make([]byte, maxFullAuditFrameBytes)}
	frame.RequestBody = frame.RequestBody[:len(frame.RequestBody)-(proto.Size(frame)-maxFullAuditFrameBytes)]
	if proto.Size(frame) != maxFullAuditFrameBytes {
		t.Fatal("fixture does not fill the frame budget")
	}
	rows := []proto.Message{frame, frame, frame, frame}
	path := writeTimelineAuditFilePlain(t, t.TempDir(), "HTTP", types.Type_NC_HTTP, rows)
	count := func() string {
		w := httptest.NewRecorder()
		HandleAuditStream(w, httptest.NewRequest(http.MethodGet, "/stream?full=true&countOnly=true", nil), path, "HTTP")
		return w.Body.String()
	}
	body := count()
	payload, ok := strings.CutPrefix(body, "event: complete\ndata: ")
	var summary struct{ Total int }
	if !ok || json.Unmarshal([]byte(payload), &summary) != nil || summary.Total != 4 {
		t.Fatalf("exact budget: %s", body)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, writeErr := f.Write([]byte{0}) // A valid empty protobuf frame still costs scan work.
	if err := f.Close(); err != nil || writeErr != nil {
		t.Fatalf("append fixture: %v, %v", writeErr, err)
	}
	if body := count(); !strings.Contains(body, "decoded audit scan exceeds 64 MiB") || strings.Contains(body, "event: complete") {
		t.Fatalf("over budget: %s", body)
	}
}

func TestAuditStreamsHoldSlotsThroughResponseWrite(t *testing.T) {
	file := writeTimelineAuditFilePlain(t, t.TempDir(), "HTTP", types.Type_NC_HTTP, []proto.Message{&types.HTTP{Method: "GET"}})
	req := func(suffix string) *http.Request {
		return httptest.NewRequest(http.MethodGet, "/api/audit/HTTP/stream"+suffix, nil)
	}
	release := make(chan struct{})
	defer func() {
		if release != nil {
			close(release)
		}
	}()
	done := make(chan *httptest.ResponseRecorder, 4)
	for range 4 {
		w := heldAlertPageResponse{httptest.NewRecorder(), make(chan struct{}, 1), release}
		go func() {
			HandleAuditStream(w, req("?full=true"), file, "HTTP")
			done <- w.ResponseRecorder
		}()
		select {
		case <-w.writing:
		case <-time.After(5 * time.Second):
			t.Fatal("admitted stream did not start writing")
		}
	}
	for _, suffix := range []string{"?countOnly=true", "?evidence=true"} {
		w := httptest.NewRecorder()
		HandleAuditStream(w, req(suffix), file, "HTTP")
		if w.Code != http.StatusTooManyRequests || strings.Contains(w.Body.String(), "event:") {
			t.Fatalf("saturated %s: %d %s", suffix, w.Code, w.Body)
		}
	}
	close(release)
	release = nil
	for range 4 {
		select {
		case w := <-done:
			if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "event: complete") {
				t.Fatalf("admitted stream: %d %s", w.Code, w.Body)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("stream did not finish")
		}
	}
	w := httptest.NewRecorder()
	HandleAuditStream(w, req("?countOnly=true"), file, "HTTP")
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "event: complete") {
		t.Fatalf("retry: %d %s", w.Code, w.Body)
	}
}

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

func TestAuditMetaDoesNotCountMislabeledOrLinkedTracks(t *testing.T) {
	dir := t.TempDir()
	file := writeTimelineAuditFilePlain(t, dir, "HTTP", types.Type_NC_UDP, []proto.Message{&types.UDP{SrcPort: 5353}})
	check := func(path, auditType string) {
		t.Helper()
		w := httptest.NewRecorder()
		HandleAuditMeta(w, httptest.NewRequest("GET", "/", nil), path, auditType)
		var result struct {
			RecordCount         int64
			RecordCountComplete bool
		}
		if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil || result.RecordCount != 0 || result.RecordCountComplete {
			t.Fatalf("unexpected metadata: %s (%v)", w.Body.String(), err)
		}
	}
	check(file, "HTTP")
	if stats := getAuditStatsForDirectory(t.Context(), dir); stats.TotalRecords != 0 {
		t.Fatalf("mislabeled track contributed %d records", stats.TotalRecords)
	}
	link := file + ".link"
	if err := os.Symlink(file, link); err != nil {
		t.Logf("symlink unavailable: %v", err)
	} else {
		check(link, "UDP")
	}
}

func TestUnsealedAuditStreamRejectsMislabeledOrLinkedTracks(t *testing.T) {
	file := writeTimelineAuditFilePlain(t, t.TempDir(), "UDP", types.Type_NC_UDP, []proto.Message{&types.UDP{SrcPort: 5353}})
	check := func(path, kind string, valid bool) {
		t.Helper()
		w := httptest.NewRecorder()
		HandleAuditStream(w, httptest.NewRequest(http.MethodGet, "/api/audit/"+kind+"/stream", nil), path, kind)
		body := w.Body.String()
		if strings.Contains(body, "event: record\n") != valid || strings.Contains(body, "event: complete\n") != valid || strings.Contains(body, "event: error\n") == valid {
			t.Fatalf("unexpected stream for %s: %s", kind, body)
		}
	}
	check(file, "UDP", true)
	check(file, "HTTP", false)
	link := filepath.Join(t.TempDir(), "UDP.ncap")
	if err := os.Symlink(file, link); err == nil {
		check(link, "UDP", false)
	} else {
		t.Logf("symlink unavailable: %v", err)
	}
}

func TestAuditInventoryRejectsOversizedDirectory(t *testing.T) {
	dir := t.TempDir()
	writeTimelineAuditFilePlain(t, dir, "HTTP", types.Type_NC_HTTP, []proto.Message{&types.HTTP{Method: "GET"}})
	for i := range maxAuditInventoryEntries {
		if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("aux-%d", i)), nil, 0600); err != nil {
			t.Fatal(err)
		}
	}
	request := func(filtered bool) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		if filtered {
			HandleAuditFilesFiltered(dir)(w, httptest.NewRequest(http.MethodGet, "/api/files/audit/filtered?communityIds=fixture", nil))
		} else {
			HandleAuditFiles(dir)(w, httptest.NewRequest(http.MethodGet, "/api/files/audit", nil))
		}
		return w
	}
	for _, filtered := range []bool{false, true} {
		if w := request(filtered); w.Code != http.StatusRequestEntityTooLarge || strings.Contains(w.Body.String(), "HTTP.ncap") {
			t.Fatalf("oversized inventory (filtered=%t) returned %d: %s", filtered, w.Code, w.Body.String())
		}
	}
	if err := os.Remove(filepath.Join(dir, "aux-0")); err != nil {
		t.Fatal(err)
	}
	for _, filtered := range []bool{false, true} {
		if w := request(filtered); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"recordCount":1`) {
			t.Fatalf("exact-limit inventory (filtered=%t) returned %d: %s", filtered, w.Code, w.Body.String())
		}
	}
}

func TestAuditInventoryQualifiesFrameCounts(t *testing.T) {
	dir := t.TempDir()
	writeTimelineAuditFilePlain(t, dir, "HTTP", types.Type_NC_UDP, []proto.Message{&types.UDP{SrcPort: 5353}})
	writeTimelineAuditFilePlain(t, dir, "UDP", types.Type_NC_UDP, []proto.Message{&types.UDP{SrcPort: 5353}})
	files, err := listAuditFiles(t.Context(), dir)
	if err != nil || len(files) != 2 {
		t.Fatalf("inventory: %v, %v", files, err)
	}
	for _, file := range files {
		wantValid := file.Type == "UDP"
		if file.RecordCountComplete == nil || *file.RecordCountComplete != wantValid || (file.RecordCount == 1) != wantValid {
			t.Fatalf("incorrect count for %s: %+v", file.Type, file)
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
