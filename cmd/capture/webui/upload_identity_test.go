package webui

import (
	"bytes"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestSameNameUploadsOwnIndependentDirectories(t *testing.T) {
	s, _, parent := reanalysisFixture(t)
	defer s.stopProcessingAdmission()
	type response struct {
		Success  bool
		ID       string `json:"sessionId"`
		Path     string
		Filename string
	}
	upload := func(data string) response {
		var body bytes.Buffer
		mw := multipart.NewWriter(&body)
		part, _ := mw.CreateFormFile("file", "x.pcap")
		part.Write([]byte(data))
		mw.Close()
		r := httptest.NewRequest(http.MethodPost, "/api/upload", &body)
		r.Header.Set("Content-Type", mw.FormDataContentType())
		w := httptest.NewRecorder()
		s.handleUpload(w, r)
		var out response
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil || !out.Success {
			t.Errorf("upload: %s %v", w.Body.String(), err)
		}
		return out
	}
	first := upload("capture A")
	firstDir, _ := s.GetFileOutputDir(first.Path)
	s.UpdateOutputDir(firstDir)
	second := upload("capture B")
	responses := []response{first, second}
	var mu sync.Mutex
	var wg sync.WaitGroup
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			out := upload("capture C")
			mu.Lock()
			responses = append(responses, out)
			mu.Unlock()
		}()
	}
	wg.Wait()
	seen := make(map[string]bool)
	for _, out := range responses {
		if out.ID == "" || seen[out.ID] || out.Filename != "x.pcap" {
			t.Fatalf("bad upload identity: %+v", out)
		}
		seen[out.ID] = true
		dir, ok := s.GetFileOutputDir(out.Path)
		if !ok || filepath.Dir(dir) != s.baseOutDir || dir == parent || filepath.Dir(out.Path) != filepath.Join(s.baseOutDir, "uploads") {
			t.Fatalf("upload escaped fixed root: %s -> %s", out.Path, dir)
		}
		r := httptest.NewRequest(http.MethodGet, "/api/audit-stats?sessionId="+url.QueryEscape(out.ID), nil)
		selected, err := s.resolveCaptureSelection(r)
		if err != nil || selected.InputFile != out.Path || selected.OutputDir != dir || selected.AnalysisID != out.ID {
			t.Fatalf("identity resolved incorrectly: %+v %v", selected, err)
		}
	}
	for _, pair := range []struct{ path, want string }{{first.Path, "capture A"}, {second.Path, "capture B"}} {
		data, err := os.ReadFile(pair.path)
		if err != nil || string(data) != pair.want {
			t.Fatalf("capture overwritten: %q %v", data, err)
		}
	}
	w := httptest.NewRecorder()
	s.handleInputFiles(w, httptest.NewRequest(http.MethodGet, "/api/files/input", nil))
	var files []FileInfo
	if err := json.Unmarshal(w.Body.Bytes(), &files); err != nil {
		t.Fatal(err)
	}
	for _, file := range files {
		if seen[file.ID] && (file.Name != "x.pcap" || file.SessionID != file.ID) {
			t.Fatalf("lost display name/identity: %+v", file)
		}
	}
}
