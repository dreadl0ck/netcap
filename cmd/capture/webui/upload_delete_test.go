package webui

import (
	"bytes"
	"encoding/json"
	"mime/multipart"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
)

func TestLocalDeletionOnlyRemovesTerminalOwnedUploads(t *testing.T) {
	s, original, parent := reanalysisFixture(t)
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	part, _ := mw.CreateFormFile("file", "owned.pcap")
	part.Write([]byte("owned capture"))
	mw.Close()
	r := httptest.NewRequest("POST", "/api/upload", &body)
	r.Header.Set("Content-Type", mw.FormDataContentType())
	w := httptest.NewRecorder()
	s.handleUpload(w, r)
	var upload struct {
		ID   string `json:"sessionId"`
		Path string
	}
	if err := json.Unmarshal(w.Body.Bytes(), &upload); err != nil || upload.ID == "" {
		t.Fatal(w.Body.String(), err)
	}
	remove := func(id string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		s.handleSessionSelect(w, httptest.NewRequest("DELETE", "/api/try/session/"+url.PathEscape(id), nil))
		return w
	}
	if w := remove(upload.ID); w.Code != 409 {
		t.Fatal("queued capture deleted", w.Code)
	}
	job := <-s.jobQueue
	job.processingDone()
	s.completedFiles[upload.Path] = true
	s.currentProcessing = job
	if w := remove(upload.ID); w.Code != 409 {
		t.Fatal("running capture deleted", w.Code)
	}
	s.currentProcessing = nil
	if w := remove(original); w.Code != 403 {
		t.Fatal("external/preloaded original admitted", w.Code)
	}
	s.fileOutputDirs[upload.Path] = parent
	if w := remove(upload.ID); w.Code != 409 {
		t.Fatal("foreign output mapping admitted", w.Code)
	}
	s.fileOutputDirs[upload.Path] = job.OutputDir
	backup := job.OutputDir + "-original"
	if err := os.Rename(job.OutputDir, backup); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(parent, job.OutputDir); err != nil {
		t.Fatal(err)
	}
	if w := remove(upload.ID); w.Code != 409 {
		t.Fatal("symlink substitution admitted", w.Code)
	}
	os.Remove(job.OutputDir)
	if err := os.Rename(backup, job.OutputDir); err != nil {
		t.Fatal(err)
	}
	s.activeInputFile, s.outDir = upload.Path, job.OutputDir
	s.fileIDToPath["alias"] = upload.Path
	timelineCache.Lock()
	timelineCache.entries[job.OutputDir] = &timelineIndexEntry{state: timelineStateReady}
	timelineCache.Unlock()
	if w := remove(upload.ID); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	for _, path := range []string{upload.Path, job.OutputDir} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatal("owned artifacts remain", path, err)
		}
	}
	if data, err := os.ReadFile(original); err != nil || string(data) != "capture fixture" {
		t.Fatal("original source changed", err)
	}
	if _, err := os.Stat(filepath.Join(parent, "HTTP.ncap.gz")); err != nil {
		t.Fatal("foreign result removed", err)
	}
	if s.fileIDToPath[upload.ID] != "" || s.fileIDToPath["alias"] != "" || s.activeInputFile != "" {
		t.Fatal("deleted capture mappings remain")
	}
	timelineCache.Lock()
	cached := timelineCache.entries[job.OutputDir] != nil
	timelineCache.Unlock()
	if cached {
		t.Fatal("deleted timeline cache remains")
	}
}

func TestServiceDeletionProtectsPreloadedRunningAndForeignSessions(t *testing.T) {
	for _, tc := range []struct {
		name, ip  string
		preloaded bool
		phase     SessionStatus
		want      int
	}{
		{"preloaded", "192.0.2.1", true, StatusCompleted, 403},
		{"running", "192.0.2.1", false, StatusProcessing, 409},
		{"queued", "192.0.2.1", false, StatusQueued, 409},
		{"foreign", "192.0.2.2", false, StatusCompleted, 404},
	} {
		t.Run(tc.name, func(t *testing.T) {
			input := filepath.Join(t.TempDir(), "original.pcap")
			os.WriteFile(input, []byte("original"), 0600)
			sm := NewSessionManager(10, 60, 10)
			sm.AddSession(&SessionInfo{SessionID: "session", InputFile: input, IP: tc.ip, Status: tc.phase, IsPreloaded: tc.preloaded})
			s := &Server{isServiceMode: true, sessionManager: sm}
			r := httptest.NewRequest("DELETE", "/api/try/session/session", nil)
			r.RemoteAddr = "192.0.2.1:1234"
			w := httptest.NewRecorder()
			s.handleSessionSelect(w, r)
			if w.Code != tc.want {
				t.Fatalf("status=%d want=%d", w.Code, tc.want)
			}
			if _, err := os.Stat(input); err != nil {
				t.Fatal("protected input removed", err)
			}
		})
	}
}
