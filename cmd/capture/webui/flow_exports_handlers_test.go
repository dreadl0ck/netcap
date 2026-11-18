package webui

import (
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFlowExportQueryLimitsConcurrentResponses(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "FlowExports.jsonl"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	health := fmt.Appendf(nil, `{"status":"done","recordsSHA256":"%x"}`, sha256.Sum256(nil))
	if err := os.WriteFile(filepath.Join(dir, "FlowExportsHealth.json"), health, 0600); err != nil {
		t.Fatal(err)
	}
	s := newTimelineTestServer(dir)
	testResponseCapacity(t, s.handleFlowExportQuery, func() *http.Request {
		return httptest.NewRequest(http.MethodGet, "/api/flows/exports/query?exporter=192.0.2.1%3A4739&format=ipfix&domain=0&startNs=1&endNs=2", nil)
	})
}

func TestFlowExportQueryDistinguishesOversizedAndInvalidDatasets(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "FlowExportsHealth.json")
	if err := os.WriteFile(path, []byte(`{"status":"invalid"}`), 0600); err != nil {
		t.Fatal(err)
	}
	s := newTimelineTestServer(dir)
	check := func(want int) {
		t.Helper()
		w := httptest.NewRecorder()
		s.handleFlowExportQuery(w, httptest.NewRequest(http.MethodGet, "/api/flows/exports/query?exporter=192.0.2.1%3A4739&format=ipfix&domain=0&startNs=1&endNs=2", nil))
		if w.Code != want {
			t.Fatalf("got HTTP %d, want %d: %s", w.Code, want, w.Body)
		}
	}
	check(http.StatusUnprocessableEntity)
	if err := os.Truncate(path, (1<<20)+1); err != nil {
		t.Fatal(err)
	}
	check(http.StatusRequestEntityTooLarge)
	// An otherwise valid event exceeds the per-event budget, not the file budget.
	data := []byte(`{"kind":"issue","issue":{"message":"` + strings.Repeat("x", 2<<20) + `"}}` + "\n")
	if err := os.WriteFile(filepath.Join(dir, "FlowExports.jsonl"), data, 0600); err != nil {
		t.Fatal(err)
	}
	health := fmt.Appendf(nil, `{"status":"done","recordsSHA256":"%x"}`, sha256.Sum256(data))
	if err := os.WriteFile(path, health, 0600); err != nil {
		t.Fatal(err)
	}
	check(http.StatusRequestEntityTooLarge)
}
