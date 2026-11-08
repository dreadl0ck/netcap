package webui

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
)

func TestStrictCaptureSelection(t *testing.T) {
	a, b := t.TempDir(), t.TempDir()
	if err := os.WriteFile(filepath.Join(b, "capture-manifest.json"), []byte(`{"runId":"generation-b"}`), 0600); err != nil {
		t.Fatal(err)
	}
	s := &Server{outDir: a, baseOutDir: a, activeInputFile: "/a.pcap", inputFiles: []string{"/a.pcap", "/b.pcap"},
		fileOutputDirs: map[string]string{"/a.pcap": a, "/b.pcap": b}, fileIDToPath: map[string]string{"child-b": "/b.pcap"}}
	for _, tc := range []struct {
		query         string
		status        int
		input, output string
	}{
		{"", 200, "/a.pcap", a},
		{"inputFile=/b.pcap", 200, "/b.pcap", b},
		{"sessionId=child-b", 200, "/b.pcap", b},
		{"sessionId=child-b&inputFile=/b.pcap&runId=generation-b", 200, "/b.pcap", b},
		{"sessionId=missing", 404, "", ""},
		{"inputFile=/unregistered.pcap", 404, "", ""},
		{"sessionId=child-b&inputFile=/a.pcap", 409, "", ""},
		{"inputFile=/b.pcap&runId=stale", 409, "", ""},
		{"inputFile=/b.pcap&scope=all", 409, "", ""},
		{"sessionId=child-b&scope=/a.pcap", 409, "", ""},
		{"inputFile=/b.pcap&inputFile=/a.pcap", 400, "", ""},
		{"sessionId=child-b&sessionId=child-b", 400, "", ""},
		{"inputFile=", 400, "", ""},
		{"runId=", 400, "", ""},
		{"runId=generation-b&runId=generation-b", 400, "", ""},
	} {
		t.Run(tc.query, func(t *testing.T) {
			called := false
			h := s.captureSelectionMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				called = true
				input, _ := s.resolveInputFileFromRequest(r)
				output, _ := s.resolveOutDirFromRequest(r)
				if input != tc.input || output != tc.output {
					t.Errorf("selection=%q %q", input, output)
				}
			}))
			w := httptest.NewRecorder()
			h.ServeHTTP(w, httptest.NewRequest("GET", "/api/http?"+tc.query, nil))
			if w.Code != tc.status || called != (tc.status == 200) {
				t.Fatalf("status=%d called=%v body=%s", w.Code, called, w.Body.String())
			}
			if tc.status != 200 {
				r := httptest.NewRequest("GET", "/?"+tc.query, nil)
				if input, ok := s.resolveInputFileFromRequest(r); ok || input != "" {
					t.Fatal("invalid source fell through")
				}
				if out, ok := s.resolveOutDirFromRequest(r); ok || out != "" {
					t.Fatal("invalid output fell through")
				}
			}
		})
	}
}

func TestCaptureSelectionPinnedWithinRequest(t *testing.T) {
	s := &Server{outDir: "output-a", activeInputFile: "input-a"}
	h := s.captureSelectionMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		s.outDir, s.activeInputFile = "output-b", "input-b"
		s.mu.Unlock()
		input, _ := s.resolveInputFileFromRequest(r)
		out, _ := s.resolveOutDirFromRequest(r)
		if input != "input-a" || out != "output-a" {
			t.Fatalf("request rebound: %s %s", input, out)
		}
	}))
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/api/http", nil))
}

func TestServiceCaptureSelectionAccess(t *testing.T) {
	t.Setenv(EnvMCPAdminToken, "synthetic-admin")
	sm := NewSessionManager(10, 60, 10)
	for id, session := range map[string]*SessionInfo{
		"own":     {IP: "192.0.2.1", InputFile: "own.pcap", OutputDir: "own-output"},
		"private": {IP: "192.0.2.2", InputFile: "private.pcap", OutputDir: "private-output"},
		"public":  {IsPreloaded: true, InputFile: "public.pcap", OutputDir: "public-output"},
	} {
		session.SessionID = id
		sm.AddSession(session)
	}
	s := &Server{isServiceMode: true, sessionManager: sm, currentSession: "own", outDir: "own-output"}
	for _, tc := range []struct {
		query, auth string
		status      int
	}{
		{"sessionId=own", "", 200}, {"sessionId=public", "", 200},
		{"sessionId=private", "", 403}, {"sessionId=private", "Bearer wrong", 403},
		{"sessionId=private", "Bearer synthetic-admin", 200},
		{"sessionId=own&inputFile=private.pcap", "", 409},
		{"inputFile=private.pcap", "", 400}, {"sessionId=missing", "", 404},
	} {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", "/api/http?"+tc.query, nil)
		r.RemoteAddr = "192.0.2.1:42460"
		r.Header.Set("Authorization", tc.auth)
		called := false
		s.captureSelectionMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true })).ServeHTTP(w, r)
		if w.Code != tc.status || called != (tc.status == 200) {
			t.Fatalf("%s status=%d body=%s", tc.query, w.Code, w.Body.String())
		}
	}
	if s.currentSession != "own" || s.outDir != "own-output" {
		t.Fatal("explicit selection mutated global state")
	}
}

func TestStaleSelectionCannotReachDataOrMutation(t *testing.T) {
	s, input, _ := reanalysisFixture(t)
	for _, handler := range []http.HandlerFunc{s.handleAuditFiles, s.handleAuditRecords, s.handleLogContent, s.handleClearAlerts} {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("POST", "/api/test?inputFile="+url.QueryEscape(input)+"&runId=stale", nil)
		s.captureSelectionMiddleware(handler).ServeHTTP(w, r)
		if w.Code != 409 {
			t.Fatalf("stale selector: %d %s", w.Code, w.Body.String())
		}
	}
}

func TestChildOutputCannotRebindActiveParent(t *testing.T) {
	s := &Server{activeInputFile: "parent", outDir: "parent-output", fileOutputDirs: make(map[string]string)}
	s.SetFileOutputDir("child", "child-output")
	if s.outDir != "parent-output" || s.activeInputFile != "parent" || s.fileOutputDirs["child"] != "child-output" {
		t.Fatal("child completion rebound active parent")
	}
}

func TestReanalysisBodyCannotRebindGeneration(t *testing.T) {
	s, input, _ := reanalysisFixture(t)
	r := httptest.NewRequest("POST", "/api/reanalyze?inputFile=/different.pcap", nil)
	if _, err := s.resolveBodyCapture(r, input, "", ""); err == nil {
		t.Fatal("body overrode explicit query")
	}
	w := requestReanalysis(s, string(mustOfflineJSON(t, map[string]string{"inputFile": input, "runId": "old-generation"})))
	if w.Code != 409 || len(s.jobQueue) != 0 {
		t.Fatalf("stale body generation admitted: %d", w.Code)
	}
}
