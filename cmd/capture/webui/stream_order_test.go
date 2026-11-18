package webui

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	streamutils "github.com/dreadl0ck/netcap/internal/decoder/stream/utils"
)

func TestStreamInventoryBoundsAggregateManifestReads(t *testing.T) {
	out := t.TempDir()
	padded := append(bytes.Repeat([]byte{' '}, 12<<20), []byte(`{"version":1,"spans":[]}`)...)
	for _, id := range []string{"stream-a", "stream-b", "stream-c"} {
		dir := filepath.Join(out, "stream-evidence", id)
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "manifest.json"), padded, 0600); err != nil {
			t.Fatal(err)
		}
	}
	s := &Server{outDir: out}
	w := httptest.NewRecorder()
	s.handleStreamEvidence(w, httptest.NewRequest("GET", "/api/investigation/streams", nil))
	if w.Code != http.StatusUnprocessableEntity || !strings.Contains(w.Body.String(), "request an individual stream by ID") {
		t.Fatalf("over-budget inventory: %d %s", w.Code, w.Body.String())
	}
	w = httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/investigation/streams?id=stream-c&direction=manifest", nil)
	r.Header.Set("Range", "bytes=0-0")
	s.handleStreamEvidence(w, r)
	if w.Code != http.StatusPartialContent || w.Body.String() != " " {
		t.Fatalf("individual stream read: %d %q", w.Code, w.Body.String())
	}
}

func TestStreamInventorySaturationPreservesIndividualReads(t *testing.T) {
	out := t.TempDir()
	dir := filepath.Join(out, "stream-evidence", "stream-fixture")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), []byte(`{"version":1,"spans":[]}`), 0600); err != nil {
		t.Fatal(err)
	}
	s := &Server{outDir: out}
	request := func(query string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		s.handleStreamEvidence(w, httptest.NewRequest("GET", "/api/investigation/streams"+query, nil))
		return w
	}
	func() {
		for range 2 {
			select {
			case streamInventorySlots <- struct{}{}:
				defer func() { <-streamInventorySlots }()
			default:
				t.Fatal("inventory did not admit two readers")
			}
		}
		if w := request(""); w.Code != http.StatusTooManyRequests {
			t.Fatalf("saturated inventory: %d %s", w.Code, w.Body.String())
		}
		if w := request("?id=stream-fixture&direction=manifest"); w.Code != http.StatusOK {
			t.Fatalf("individual manifest during saturation: %d %s", w.Code, w.Body.String())
		}
	}()
	if w := request(""); w.Code != http.StatusOK {
		t.Fatalf("inventory did not recover: %d %s", w.Code, w.Body.String())
	}
}

func TestStreamEvidenceOrdersByCaptureIdentity(t *testing.T) {
	for _, order := range [][]string{{"stream-z", "stream-a", "stream-m"}, {"stream-m", "stream-a", "stream-z"}} {
		out := t.TempDir()
		for _, id := range order {
			timestamp := map[string]string{"stream-z": "200", "stream-a": "300", "stream-m": "100"}[id]
			dir := filepath.Join(out, "stream-evidence", id)
			if err := os.MkdirAll(dir, 0700); err != nil {
				t.Fatal(err)
			}
			manifest := streamutils.StreamEvidenceManifest{Version: 1, FirstPacketNs: timestamp, ConnectionKey: id}
			if id == "stream-m" {
				manifest.Spans = make([]streamutils.StreamEvidenceSpan, 50000)
			}
			raw, err := json.Marshal(manifest)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, "manifest.json"), raw, 0600); err != nil {
				t.Fatal(err)
			}
		}
		s := &Server{outDir: out}
		w := httptest.NewRecorder()
		s.handleStreamEvidence(w, httptest.NewRequest("GET", "/api/investigation/streams", nil))
		var rows []struct {
			ID           string
			SpanCount    int
			SpansOmitted bool
			Manifest     streamutils.StreamEvidenceManifest
		}
		if err := json.Unmarshal(w.Body.Bytes(), &rows); err != nil || w.Code != 200 {
			t.Fatal(err, w.Body.String())
		}
		if len(rows) != 3 || rows[0].ID != "stream-m" || rows[1].ID != "stream-z" || rows[2].ID != "stream-a" {
			t.Fatalf("directory order leaked into capture ordering: %+v", rows)
		}
		if row := rows[0]; row.SpanCount != 50000 || !row.SpansOmitted || len(row.Manifest.Spans) != 0 || row.Manifest.ConnectionKey != row.ID {
			t.Fatalf("inventory lost span count or metadata: %+v", row)
		}
	}
}
