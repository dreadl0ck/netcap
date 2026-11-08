package webui

import (
	"context"
	"encoding/json"
	"github.com/dreadl0ck/netcap/internal/decoder/stream/file"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestArtifactReadersConfinedAndSelected(t *testing.T) {
	out := t.TempDir()
	root := filepath.Join(out, "files")
	if err := os.MkdirAll(filepath.Join(root, "nested"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "nested", "owned"), []byte("owned content"), 0600); err != nil {
		t.Fatal(err)
	}
	sibling := filepath.Join(out, "files-other")
	if err := os.Mkdir(sibling, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sibling, "secret"), []byte("PRIVATE_SENTINEL"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(sibling, "secret"), filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
	s := &Server{outDir: out}
	handlers := []struct {
		prefix  string
		handler http.HandlerFunc
	}{{"/api/extracted-files/download/", s.handleDownloadExtractedFile}, {"/api/extracted-files/content/", s.handleExtractedFileContent}}
	for _, h := range handlers {
		for _, name := range []string{"../files-other/secret", "link", "nested/../../files-other/secret"} {
			r := httptest.NewRequest("GET", h.prefix+url.PathEscape(name), nil)
			w := httptest.NewRecorder()
			h.handler(w, r)
			if w.Code < 400 || strings.Contains(w.Body.String(), "PRIVATE_SENTINEL") {
				t.Fatalf("unsafe %s: %d %s", name, w.Code, w.Body.String())
			}
		}
		r := httptest.NewRequest("GET", h.prefix+"nested%2Fowned", nil)
		w := httptest.NewRecorder()
		h.handler(w, r)
		if w.Code != 200 {
			t.Fatalf("valid: %d %s", w.Code, w.Body.String())
		}
		r = httptest.NewRequest("GET", h.prefix+"nested%2Fowned?inputFile=unknown", nil)
		w = httptest.NewRecorder()
		h.handler(w, r)
		if w.Code != 404 {
			t.Fatal("unknown capture fell back to current capture")
		}
	}
	for _, name := range []string{"../files-other/secret", "link"} {
		r := scanArtifact(context.Background(), root, name, &file.YaraScanner{})
		if r.State == "completed" || len(r.Matches) > 0 {
			t.Fatal("scan accepted escaped artifact")
		}
	}
}

func TestArtifactAnalysisMissingInvalidAndComplete(t *testing.T) {
	out := t.TempDir()
	s := &Server{outDir: out}
	request := func() *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		s.handleArtifactAnalysis(w, httptest.NewRequest("GET", "/api/artifact-analysis", nil))
		return w
	}
	if w := request(); w.Code != 404 {
		t.Fatal("legacy absent report became clean")
	}
	if err := os.WriteFile(filepath.Join(out, file.AnalysisReportFile), []byte("broken"), 0600); err != nil {
		t.Fatal(err)
	}
	if w := request(); w.Code != 500 {
		t.Fatal("corrupt report became clean")
	}
	b, _ := json.Marshal(file.AnalysisReport{Version: 1, RunID: "fixture", State: "partial", Results: map[string]*file.ArtifactAnalysis{}, Rejected: 1})
	if err := os.WriteFile(filepath.Join(out, file.AnalysisReportFile), b, 0600); err != nil {
		t.Fatal(err)
	}
	w := request()
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"state":"partial"`) {
		t.Fatalf("status lost: %d %s", w.Code, w.Body.String())
	}
}

func TestNativeSingleArtifactScanStatus(t *testing.T) {
	out, rulesDir := t.TempDir(), t.TempDir()
	if err := os.Mkdir(filepath.Join(out, "files"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(out, "files", "owned"), []byte("OWNED_SCAN"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(rulesDir, "owned.yar"), []byte(`rule owned { strings: $x="OWNED_SCAN" condition:$x }`), 0600); err != nil {
		t.Fatal(err)
	}
	file.ResetGlobalYaraScanner()
	defer file.ResetGlobalYaraScanner()
	if file.YaraAvailable() {
		if _, err := file.InitGlobalYaraScanner(rulesDir); err != nil {
			t.Fatal(err)
		}
	}
	s := &Server{outDir: out}
	w := httptest.NewRecorder()
	s.handleYaraScanFile(w, httptest.NewRequest("POST", "/api/yara/scan-file", strings.NewReader(`{"filePath":"owned"}`)))
	if !file.YaraAvailable() {
		if w.Code != 503 {
			t.Fatal("unsupported scanner claimed success")
		}
		return
	}
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"outcome":"matched"`) {
		t.Fatalf("native scan: %d %s", w.Code, w.Body.String())
	}
	w = httptest.NewRecorder()
	s.handleYaraScanFile(w, httptest.NewRequest("POST", "/api/yara/scan-file", strings.NewReader(`{"filePath":"../sentinel"}`)))
	if w.Code != 422 {
		t.Fatal("scan route accepted traversal")
	}
}
