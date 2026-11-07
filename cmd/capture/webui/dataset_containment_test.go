//go:build !appstore

package webui

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dreadl0ck/netcap/internal/resolvers"
	"github.com/dreadl0ck/netcap/internal/servicesignatures"
)

func TestRetiredDatasetAPIs(t *testing.T) {
	old := resolvers.DataBaseFolderPath
	resolvers.DataBaseFolderPath = t.TempDir()
	t.Cleanup(func() { resolvers.DataBaseFolderPath = old })
	path := filepath.Join(resolvers.DataBaseFolderPath, "nmap-service-probes")
	const sentinel = "legacy content must not be returned or modified"
	if err := os.WriteFile(path, []byte(sentinel), 0600); err != nil {
		t.Fatal(err)
	}
	s := &Server{}
	mux := http.NewServeMux()
	registerEditionRoutes(mux, s)
	mux.HandleFunc("/api/vulnerabilities/exploit-file", s.handleExploitFileContent)
	for _, url := range []string{"/api/service-probes", "/api/service-probes/example", "/api/service-probes/test", "/api/service-probes/export", "/api/service-probes/import", "/api/vulnerabilities/exploit-file?file=../../secret"} {
		for _, method := range []string{"GET", "POST", "PUT", "DELETE", "PATCH"} {
			w := httptest.NewRecorder()
			mux.ServeHTTP(w, httptest.NewRequest(method, url, strings.NewReader(sentinel)))
			if w.Code != http.StatusGone || strings.Contains(w.Body.String(), sentinel) {
				t.Fatalf("%s %s: %d %s", method, url, w.Code, w.Body.String())
			}
		}
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != sentinel {
		t.Fatal("legacy file changed")
	}
}

func TestCaptureSignatureStatusDoesNotReloadCatalogue(t *testing.T) {
	dir := t.TempDir()
	s := &Server{outDir: dir}
	request := func() servicesignatures.Inventory {
		t.Helper()
		w := httptest.NewRecorder()
		s.handleServiceSignatureStatus(w, httptest.NewRequest("GET", "/api/service-signatures/status", nil))
		if w.Code != 200 {
			t.Fatalf("%d: %s", w.Code, w.Body.String())
		}
		var i servicesignatures.Inventory
		if err := json.Unmarshal(w.Body.Bytes(), &i); err != nil {
			t.Fatal(err)
		}
		return i
	}
	if i := request(); i.State != "not-recorded" || i.Source != "none" {
		t.Fatalf("invented runtime state: %+v", i)
	}
	i := servicesignatures.Builtin().Inventory("capture", os.ErrNotExist)
	if err := servicesignatures.WriteInventory(dir, i); err != nil {
		t.Fatal(err)
	}
	// Runtime diagnostics must survive changes to the next-capture catalogue.
	if err := os.WriteFile(filepath.Join(dir, servicesignatures.FileName), []byte("invalid"), 0600); err != nil {
		t.Fatal(err)
	}
	got := request()
	if got.SourceSHA256 != i.SourceSHA256 || !got.CheckedAt.Equal(i.CheckedAt) || got.Warning != i.Warning {
		t.Fatalf("runtime snapshot was replaced: %+v", got)
	}
}

func TestReadOnlyServiceSignatureCatalogue(t *testing.T) {
	t.Setenv("NC_ENRICHMENT_ROOT", filepath.Join(t.TempDir(), "absent-enrichment"))
	old := resolvers.DataBaseFolderPath
	resolvers.DataBaseFolderPath = t.TempDir()
	t.Cleanup(func() { resolvers.DataBaseFolderPath = old })
	s := &Server{}
	w := httptest.NewRecorder()
	s.handleServiceSignatures(w, httptest.NewRequest("GET", "/api/service-signatures", nil))
	var got struct {
		Degraded  bool   `json:"degraded"`
		Warning   string `json:"warning"`
		Catalogue struct {
			Format string `json:"format"`
		} `json:"catalogue"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if w.Code != 200 || !got.Degraded || got.Warning == "" || got.Catalogue.Format != "netcap-service-signatures" {
		t.Fatalf("%s", w.Body.String())
	}
	w = httptest.NewRecorder()
	s.handleServiceSignatures(w, httptest.NewRequest("POST", "/api/service-signatures", nil))
	if w.Code != 405 {
		t.Fatal(w.Code)
	}
}
