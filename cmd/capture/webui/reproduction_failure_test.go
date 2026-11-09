package webui

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func failedReproductionFixture(t *testing.T, service bool) (*Server, *AnalysisJob, []byte) {
	t.Helper()
	root := t.TempDir()
	input := filepath.Join(root, "synthetic-invalid.pcap")
	data := []byte(strings.Repeat("x", 80))
	if err := os.WriteFile(input, data, 0600); err != nil {
		t.Fatal(err)
	}
	s := &Server{outDir: root, baseOutDir: root, activeInputFile: "other.pcap", inputFiles: []string{input},
		fileErrors: make(map[string]FileError), fileIDToPath: map[string]string{"owned": input},
		jobQueue: make(chan *AnalysisJob, 1), isServiceMode: service}
	if service {
		s.sessionManager = NewSessionManager(10, 60, 10)
		s.sessionManager.AddSession(&SessionInfo{SessionID: "owned", IP: "192.0.2.1", InputFile: input, OutputDir: filepath.Join(root, "missing-output"), Status: StatusQueued})
	}
	job := &AnalysisJob{InputFile: input, SessionID: "owned", OutputDir: filepath.Join(root, "missing-output"), ArtifactConfig: []byte("RAW_SECRET_SENTINEL"), BPFFilter: "RAW_SECRET_SENTINEL"}
	if err := s.enqueueAnalysis(job, false); err != nil {
		t.Fatal(err)
	}
	if received := <-s.jobQueue; received != job {
		t.Fatal("wrong job admitted")
	}
	t.Cleanup(job.processingDone)
	s.recordAnalysisFailure(job, "RAW_SECRET_SENTINEL", "")
	return s, job, data
}

func failureReproductionRequest(s *Server, query, ip, token string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("GET", "/api/investigation/reproduction?"+query, nil)
	r.RemoteAddr = ip
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	s.captureSelectionMiddleware(http.HandlerFunc(s.handleReproductionBundle)).ServeHTTP(w, r)
	return w
}

func TestFailedReproductionWithoutManifestOrOutput(t *testing.T) {
	s, job, admitted := failedReproductionFixture(t, false)
	// A single failed upload used to resolve to the active/base directory instead.
	if err := os.WriteFile(filepath.Join(s.baseOutDir, "capture-manifest.json"), []byte(`{"version":1,"runId":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","status":"done","inputSHA256":"WRONG_CAPTURE"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(job.InputFile); err != nil {
		t.Fatal(err)
	}
	w := failureReproductionRequest(s, "sessionId=owned", "127.0.0.1:1234", "")
	if w.Code != 200 {
		t.Fatalf("failed metadata: %d %s", w.Code, w.Body.String())
	}
	var result map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result["sourceSHA256"] != digestBytes(admitted) || result["sourceBytes"] != "80" || result["metadataBasis"] != "failed-job-admission" || result["runId"] != "unavailable" || result["captureStatus"] != "error" {
		t.Fatalf("unbound or fabricated metadata: %s", w.Body.String())
	}
	if !strings.Contains(w.Body.String(), `"name":"capture-manifest.json","state":"missing"`) || !strings.Contains(w.Body.String(), `"state":"unavailable"`) {
		t.Fatalf("missing provenance not explicit: %s", w.Body.String())
	}
	for _, secret := range []string{"RAW_SECRET_SENTINEL", "WRONG_CAPTURE", job.InputFile, job.OutputDir} {
		if strings.Contains(w.Body.String(), secret) {
			t.Fatalf("metadata leaked %q", secret)
		}
	}
	if s.activeInputFile != "other.pcap" || s.outDir != s.baseOutDir {
		t.Fatal("failed metadata changed the active capture")
	}
	for query, status := range map[string]int{"sessionId=unknown": 404, "inputFile=/unregistered": 404, "sessionId=owned&inputFile=/other": 409, "sessionId=owned&runId=stale": 409, "sessionId=owned&reviewedLog=true": 409} {
		if got := failureReproductionRequest(s, query, "127.0.0.1:1234", ""); got.Code != status {
			t.Fatalf("%s: %d %s", query, got.Code, got.Body.String())
		}
	}
	selected := failureReproductionRequest(s, "inputFile="+url.QueryEscape(job.InputFile), "127.0.0.1:1234", "")
	if selected.Code != 200 {
		t.Fatalf("explicit source selector lost admitted binding: %d", selected.Code)
	}
}

func TestFailedReproductionPreservesSessionAuthorization(t *testing.T) {
	t.Setenv(EnvMCPAdminToken, "synthetic-admin")
	s, _, _ := failedReproductionFixture(t, true)
	for _, tc := range []struct {
		ip, token string
		status    int
	}{{"192.0.2.1:1234", "", 200}, {"192.0.2.2:1234", "", 403}, {"192.0.2.2:1234", "wrong", 403}, {"192.0.2.2:1234", "synthetic-admin", 200}} {
		w := failureReproductionRequest(s, "sessionId=owned", tc.ip, tc.token)
		if w.Code != tc.status {
			t.Fatalf("private failure metadata: %d %s", w.Code, w.Body.String())
		}
	}
}

func TestFailedReproductionDoesNotMaskCorruptOrUnsafeManifest(t *testing.T) {
	s, job, _ := failedReproductionFixture(t, false)
	if err := os.Mkdir(job.OutputDir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(job.OutputDir, "capture-manifest.json")
	if err := os.WriteFile(path, []byte("not JSON"), 0600); err != nil {
		t.Fatal(err)
	}
	if w := failureReproductionRequest(s, "sessionId=owned", "127.0.0.1:1234", ""); w.Code != 422 {
		t.Fatalf("corrupt manifest hidden by fallback: %d", w.Code)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(job.InputFile, path); err != nil {
		t.Fatal(err)
	}
	if w := failureReproductionRequest(s, "sessionId=owned", "127.0.0.1:1234", ""); w.Code != 500 {
		t.Fatalf("unsafe manifest hidden by fallback: %d", w.Code)
	}
}
