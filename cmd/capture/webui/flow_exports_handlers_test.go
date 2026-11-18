package webui

import (
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
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
