package webui

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func reanalysisFixture(t *testing.T) (*Server, string, string) {
	t.Helper()
	root := t.TempDir()
	input := filepath.Join(root, "input.pcap")
	parent := filepath.Join(root, "parent")
	if err := os.Mkdir(parent, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(parent, "files"), 0700); err != nil {
		t.Fatal(err)
	}
	for path, data := range map[string]string{input: "capture fixture", filepath.Join(parent, "HTTP.ncap.gz"): "parent results", filepath.Join(parent, "notes.json"): "parent notes", filepath.Join(parent, "files", "artifact"): "parent artifact", filepath.Join(parent, "capture-manifest.json"): `{"version":1,"runId":"parent-run","status":"complete"}`} {
		if err := os.WriteFile(path, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	return &Server{baseOutDir: root, outDir: parent, inputFiles: []string{input},
		completedFiles: map[string]bool{input: true}, fileOutputDirs: map[string]string{input: parent},
		fileProcessingTime: map[string]float64{input: 12.5}, fileErrors: make(map[string]FileError),
		fileIDToPath: make(map[string]string), jobQueue: make(chan *AnalysisJob, 8)}, input, parent
}

func requestReanalysis(s *Server, body string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/reanalyze", strings.NewReader(body))
	r.RemoteAddr = "192.0.2.1:4321"
	s.handleReanalyze(w, r)
	return w
}

func assertParentPreserved(t *testing.T, s *Server, input, parent string) {
	t.Helper()
	for path, want := range map[string]string{"HTTP.ncap.gz": "parent results", "notes.json": "parent notes", "files/artifact": "parent artifact"} {
		data, err := os.ReadFile(filepath.Join(parent, path))
		if err != nil || string(data) != want {
			t.Fatalf("parent %s changed: %q %v", path, data, err)
		}
	}
	if !s.completedFiles[input] || s.fileProcessingTime[input] != 12.5 || s.fileOutputDirs[input] != parent {
		t.Fatal("parent state changed")
	}
	if _, ok := s.fileErrors[input]; ok {
		t.Fatal("child error applied to parent")
	}
}

func TestReanalysisCreatesDistinctChildRuns(t *testing.T) {
	s, input, parent := reanalysisFixture(t)
	for range 2 {
		w := requestReanalysis(s, string(mustOfflineJSON(t, map[string]string{"inputFile": input})))
		if w.Code != 200 {
			t.Fatalf("status=%d %s", w.Code, w.Body.String())
		}
		job := <-s.jobQueue
		defer job.processingDone()
		if job.InputFile == input || job.OutputDir == parent || filepath.Dir(job.OutputDir) != filepath.Dir(parent) {
			t.Fatalf("child is not isolated: %+v", job)
		}
		var provenance childAnalysis
		data, err := os.ReadFile(filepath.Join(job.OutputDir, "analysis-parent.json"))
		if err != nil || json.Unmarshal(data, &provenance) != nil {
			t.Fatalf("provenance=%q err=%v", data, err)
		}
		hash := sha256.Sum256([]byte("capture fixture"))
		if provenance.AnalysisID != job.SessionID || provenance.Selector != "whole-capture" || provenance.ParentRunID != "parent-run" || provenance.ParentOutputDir != parent || provenance.InputSHA256 != hex.EncodeToString(hash[:]) || len(provenance.ParentManifestSHA256) != 64 || !bytes.Equal(provenance.ArtifactConfig, job.ArtifactConfig) {
			t.Fatalf("provenance=%+v", provenance)
		}
		// Worker failures and cancellation must target only the child.
		s.recordAnalysisFailure(job, "child failed", "")
		if s.fileErrors[job.InputFile].Error == "" {
			t.Fatal("child failure missing")
		}
		assertParentPreserved(t, s, input, parent)
	}
	w := httptest.NewRecorder()
	s.handleInputFiles(w, httptest.NewRequest(http.MethodGet, "/api/files/input", nil))
	var files []FileInfo
	if err := json.Unmarshal(w.Body.Bytes(), &files); err != nil || len(files) != 3 {
		t.Fatalf("files=%s err=%v", w.Body.String(), err)
	}
	ids := make(map[string]bool)
	for _, file := range files {
		if ids[file.ID] || s.fileIDToPath[file.ID] != file.Path {
			t.Fatalf("same-content runs collide: %+v", files)
		}
		ids[file.ID] = true
		if file.Path != input && file.ParentInputFile != input {
			t.Fatalf("parent link missing: %+v", file)
		}
	}
	// The child's source is independent of subsequent changes to the parent input.
	if err := os.WriteFile(input, []byte("replacement"), 0600); err != nil {
		t.Fatal(err)
	}
	for childInput := range s.childAnalyses {
		data, err := os.ReadFile(childInput)
		if err != nil || string(data) != "capture fixture" {
			t.Fatalf("child source changed: %q %v", data, err)
		}
	}
}

func TestReanalysisFailurePreservesParent(t *testing.T) {
	for _, scenario := range []string{"missing", "unavailable", "full", "stopping", "changed-source", "invalid-manifest"} {
		t.Run(scenario, func(t *testing.T) {
			s, input, parent := reanalysisFixture(t)
			want := 503
			switch scenario {
			case "missing":
				os.Remove(input)
				want = 404
			case "unavailable":
				s.jobQueue = nil
			case "full":
				s.jobQueue = make(chan *AnalysisJob)
			case "stopping":
				s.processingStopping = true
			case "changed-source":
				os.WriteFile(filepath.Join(parent, "capture-manifest.json"), []byte(`{"inputSHA256":"different"}`), 0600)
				want = 409
			case "invalid-manifest":
				os.WriteFile(filepath.Join(parent, "capture-manifest.json"), []byte(`{`), 0600)
				want = 409
			}
			w := requestReanalysis(s, string(mustOfflineJSON(t, map[string]string{"inputFile": input})))
			if w.Code != want {
				t.Fatalf("status=%d want=%d %s", w.Code, want, w.Body.String())
			}
			assertParentPreserved(t, s, input, parent)
			if s.processingWork != 0 || s.jobsScheduled != 0 {
				t.Fatal("rejected admission leaked work")
			}
		})
	}
}

func TestServiceReanalysisOwnsChildAndPreservesParent(t *testing.T) {
	s, input, parent := reanalysisFixture(t)
	s.isServiceMode = true
	s.sessionManager = NewSessionManager(10, 60, 10)
	original := SessionInfo{SessionID: "parent", IP: "192.0.2.1", InputFile: input, OutputDir: parent,
		Status: StatusCompleted, ResultsReady: true, ProcessingTime: 12.5, IsPreloaded: true}
	s.sessionManager.AddSession(&original)
	before := original
	w := requestReanalysis(s, `{"sessionId":"parent"}`)
	if w.Code != 200 {
		t.Fatalf("status=%d %s", w.Code, w.Body.String())
	}
	job := <-s.jobQueue
	defer job.processingDone()
	child, ok := s.sessionManager.GetSession(job.SessionID)
	if !ok || child.ParentSessionID != "parent" || child.IsPreloaded || child.IP != "192.0.2.1" || child.ResultsReady || child.Status != StatusQueued || child.InputFile == input {
		t.Fatalf("child=%+v", child)
	}
	storedParent, _ := s.sessionManager.GetSession("parent")
	if !reflect.DeepEqual(*storedParent, before) {
		t.Fatalf("parent modified: %+v", storedParent)
	}
	assertParentPreserved(t, s, input, parent)
	for _, tc := range []struct {
		body string
		code int
	}{
		{`{"inputFile":"anything"}`, 400},
		{`{"sessionId":"unknown"}`, 404},
		{`{"sessionId":"parent","inputFile":"other"}`, 409},
	} {
		w := requestReanalysis(s, tc.body)
		if w.Code != tc.code {
			t.Fatalf("%s: status=%d %s", tc.body, w.Code, w.Body.String())
		}
	}
}

func TestServiceReanalysisDeniesPrivateParent(t *testing.T) {
	s, input, parent := reanalysisFixture(t)
	s.isServiceMode = true
	s.sessionManager = NewSessionManager(10, 60, 10)
	s.sessionManager.AddSession(&SessionInfo{SessionID: "private", IP: "192.0.2.2", InputFile: input,
		OutputDir: parent, Status: StatusCompleted, ResultsReady: true})
	w := requestReanalysis(s, `{"sessionId":"private"}`)
	if w.Code != http.StatusForbidden || len(s.sessionManager.GetAllSessions()) != 1 || len(s.jobQueue) != 0 {
		t.Fatalf("private parent admitted: %d %s", w.Code, w.Body.String())
	}
	assertParentPreserved(t, s, input, parent)
}

func TestQueuedChildCancellationPreservesParent(t *testing.T) {
	s, input, parent := reanalysisFixture(t)
	w := requestReanalysis(s, string(mustOfflineJSON(t, map[string]string{"inputFile": input})))
	if w.Code != http.StatusOK {
		t.Fatalf("admission: %d %s", w.Code, w.Body.String())
	}
	s.stopProcessingAdmission()
	if s.processingWork != 0 || len(s.jobQueue) != 0 {
		t.Fatal("canceled child retained queued work")
	}
	for child := range s.childAnalyses {
		if !strings.Contains(s.fileErrors[child].Error, "canceled") {
			t.Fatal("child cancellation was not recorded")
		}
	}
	assertParentPreserved(t, s, input, parent)
}

func TestCanceledWholeChildPreparationPreservesParent(t *testing.T) {
	s, input, parent := reanalysisFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r := httptest.NewRequest(http.MethodPost, "/api/reanalyze", bytes.NewReader(mustOfflineJSON(t, map[string]string{"inputFile": input}))).WithContext(ctx)
	w := httptest.NewRecorder()
	s.handleReanalyze(w, r)
	if w.Code != http.StatusRequestTimeout || len(s.jobQueue) != 0 || len(s.childAnalyses) != 0 {
		t.Fatalf("canceled copy admitted work: %d %s", w.Code, w.Body.String())
	}
	assertParentPreserved(t, s, input, parent)
}
