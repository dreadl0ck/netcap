package webui

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dreadl0ck/netcap/internal/evidence"
)

func TestReproductionMetadataOmitsRawSecretsAndRecordsAttachmentOutcomes(t *testing.T) {
	dir := t.TempDir()
	secret := "RAW_SECRET_SENTINEL"
	manifest := evidence.CaptureManifest{Version: 1, RunID: strings.Repeat("a", 32), Status: "error", Error: secret,
		InputSHA256: strings.Repeat("b", 64), ConfigSHA256: strings.Repeat("c", 64),
		Config: evidence.CaptureConfig{Source: secret, BPF: secret, IncludeDecoders: secret, ExcludeDecoders: secret, Workers: 4, SnapLen: 65535, Reassembly: true}}
	data, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "capture-manifest.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "analysis-parent.json"), []byte(`{"sensitive":"`+secret+`"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "artifact-analysis.json"), []byte("corrupt "+secret), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "packet-selection.json"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "netcap.log"), []byte(secret), 0600); err != nil {
		t.Fatal(err)
	}
	s := &Server{outDir: dir}
	w := httptest.NewRecorder()
	s.handleReproductionBundle(w, httptest.NewRequest("GET", "/api/investigation/reproduction?runId="+manifest.RunID, nil))
	if w.Code != 200 || strings.Contains(w.Body.String(), secret) {
		t.Fatalf("unsafe bundle: %d %s", w.Code, w.Body.String())
	}
	for _, want := range []string{`"captureStatus":"error"`, `"state":"metadata-only"`, `"state":"missing"`, `"state":"invalid-json"`, `"state":"read-failed"`, `"state":"omitted-sensitive"`, `"workers":4`, `"producerVersion":"unavailable"`, manifest.InputSHA256} {
		if !strings.Contains(w.Body.String(), want) {
			t.Fatalf("missing %s in %s", want, w.Body.String())
		}
	}
	if !strings.Contains(w.Header().Get("Content-Disposition"), "attachment") {
		t.Fatal("missing attachment header")
	}
}

func TestReproductionRefusesMissingStaleUnknownAndSymlink(t *testing.T) {
	dir := t.TempDir()
	s := &Server{outDir: dir}
	for _, tc := range []struct {
		query  string
		status int
	}{{"", 404}, {"?runId=stale", 409}, {"?inputFile=unknown", 404}, {"?inputFile=unknown&inputFile=other", 400}} {
		w := httptest.NewRecorder()
		s.handleReproductionBundle(w, httptest.NewRequest("GET", "/api/investigation/reproduction"+tc.query, nil))
		if w.Code != tc.status {
			t.Fatalf("%s: %d %s", tc.query, w.Code, w.Body.String())
		}
	}
	external := filepath.Join(t.TempDir(), "private")
	if err := os.WriteFile(external, []byte(`{"secret":"OUTSIDE_SENTINEL"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(external, filepath.Join(dir, "capture-manifest.json")); err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	s.handleReproductionBundle(w, httptest.NewRequest("GET", "/api/investigation/reproduction", nil))
	if w.Code != 500 || strings.Contains(w.Body.String(), "OUTSIDE_SENTINEL") {
		t.Fatalf("unsafe path: %d %s", w.Code, w.Body.String())
	}
}

func TestLogDirectoryReadFailureIsNotEmptySuccess(t *testing.T) {
	w := httptest.NewRecorder()
	HandleLogFiles(filepath.Join(t.TempDir(), "missing"))(w, httptest.NewRequest("GET", "/api/files/logs", nil))
	if w.Code != 500 {
		t.Fatalf("missing log directory became empty success: %d", w.Code)
	}
}

func TestAnalystEvidenceHandlersEnforcePrivateSessionOwnership(t *testing.T) {
	s := &Server{isServiceMode: true, sessionManager: &SessionManager{sessions: map[string]*SessionInfo{
		"private": {SessionID: "private", IP: "192.0.2.1", OutputDir: t.TempDir(), Status: StatusFailed},
	}}}
	for _, handler := range []http.HandlerFunc{s.handleReproductionBundle, s.handleHosts, s.handleSoftware} {
		r := httptest.NewRequest("GET", "/api/owned?sessionId=private", nil)
		r.RemoteAddr = "192.0.2.2:12345"
		w := httptest.NewRecorder()
		handler(w, r)
		if w.Code != http.StatusForbidden {
			t.Fatalf("private capture leaked: %d %s", w.Code, w.Body.String())
		}
	}
}
