package webui

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/internal/decoder/core"
	streamutils "github.com/dreadl0ck/netcap/internal/decoder/stream/utils"
	"github.com/dreadl0ck/netcap/internal/evidence"
	"github.com/dreadl0ck/netcap/internal/reassembly"
)

func TestInvestigationHealthPreservesExactCounters(t *testing.T) {
	dir := t.TempDir()
	const counter = "9007199254740993"
	path := filepath.Join(dir, "TCPReassemblyHealth.json")
	if err := os.WriteFile(path, []byte(`{"bytes":`+counter+`}`), 0600); err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	(&Server{outDir: dir}).handleInvestigationHealth(w, httptest.NewRequest(http.MethodGet, "/?kind=reassembly", nil))
	if w.Code != http.StatusOK || strings.TrimSpace(w.Body.String()) != `{"bytes":`+counter+`}` {
		t.Fatalf("health response: %d %s", w.Code, w.Body)
	}
}

func TestInvestigationJSONRejectsLinkedFiles(t *testing.T) {
	dir := t.TempDir()
	external := filepath.Join(t.TempDir(), "fixture.json")
	if err := os.WriteFile(external, []byte(`{"status":"fixture"}`), 0600); err != nil {
		t.Fatal(err)
	}
	s := &Server{outDir: dir}
	for _, tc := range []struct {
		name, query string
		handler http.HandlerFunc
	}{
		{"capture-manifest.json", "/", s.handleCaptureEvidence},
		{"FTPDataHealth.json", "/?kind=ftp", s.handleInvestigationHealth},
	} {
		if err := os.Symlink(external, filepath.Join(dir, tc.name)); err != nil {
			t.Fatal(err)
		}
		w := httptest.NewRecorder()
		tc.handler(w, httptest.NewRequest(http.MethodGet, tc.query, nil))
		if w.Code != http.StatusUnprocessableEntity || strings.Contains(w.Body.String(), `"status":"fixture"`) {
			t.Fatalf("%s: expected linked evidence refusal, got %d %s", tc.name, w.Code, w.Body)
		}
	}
}

func TestInvestigationEvidenceEndpoints(t *testing.T) {
	dir := t.TempDir()
	server := &Server{outDir: dir}
	if path, ok := server.resolveEvidenceOutput(httptest.NewRequest("GET", "/?inputFile=unknown.pcap", nil)); ok || path != "" {
		t.Fatal("unknown explicit selection fell back to active evidence")
	}
	response := httptest.NewRecorder()
	server.handleCaptureEvidence(response, httptest.NewRequest("GET", "/", nil))
	if response.Code != http.StatusUnprocessableEntity {
		t.Fatal("missing provenance returned as healthy")
	}
	capture, err := evidence.NewCapture(context.Background(), dir, evidence.CaptureConfig{Kind: "live", Source: "fixture0"})
	if err != nil {
		t.Fatal(err)
	}
	if err := capture.Close("stopped", 0, 0, nil); err != nil {
		t.Fatal(err)
	}
	response = httptest.NewRecorder()
	server.handleCaptureEvidence(response, httptest.NewRequest("GET", "/", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("manifest response: %s", response.Body)
	}
	stream, err := streamutils.SaveStreamEvidence(dir, "TCP", core.DataFragments{&core.StreamData{RawData: []byte{0, 255, 27}, Dir: reassembly.TCPDirClientToServer}}, "fixture", time.Unix(1, 0), "cid")
	if err != nil {
		t.Fatal(err)
	}
	response = httptest.NewRecorder()
	server.handleStreamEvidence(response, httptest.NewRequest("GET", "/?id="+filepath.Base(stream)+"&direction=client", nil))
	if response.Code != 200 || string(response.Body.Bytes()) != string([]byte{0, 255, 27}) {
		t.Fatalf("raw stream altered: %d %x", response.Code, response.Body.Bytes())
	}
	response = httptest.NewRecorder()
	request := httptest.NewRequest("GET", "/?id="+filepath.Base(stream)+"&direction=client", nil)
	request.Header.Set("Range", "bytes=1-2")
	server.handleStreamEvidence(response, request)
	if response.Code != http.StatusPartialContent || response.Header().Get("Content-Range") != "bytes 1-2/3" || !bytes.Equal(response.Body.Bytes(), []byte{255, 27}) {
		t.Fatalf("stream range altered: %d %v %x", response.Code, response.Header(), response.Body.Bytes())
	}
	response = httptest.NewRecorder()
	server.handleStreamEvidence(response, httptest.NewRequest("GET", "/?id=../../outside&direction=client", nil))
	if response.Code != 400 {
		t.Fatal("accepted invalid stream identity")
	}
	outside := filepath.Join(t.TempDir(), "outside.bin")
	if err := os.WriteFile(outside, []byte("outside"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(stream, "server.bin")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(stream, "server.bin")); err != nil {
		t.Fatal(err)
	}
	response = httptest.NewRecorder()
	server.handleStreamEvidence(response, httptest.NewRequest("GET", "/?id="+filepath.Base(stream)+"&direction=server", nil))
	if response.Code != 400 {
		t.Fatal("escaped stream root")
	}
	manifest := filepath.Join(stream, "manifest.json")
	externalManifest := filepath.Join(t.TempDir(), "manifest.json")
	if err := os.Rename(manifest, externalManifest); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(externalManifest, manifest); err != nil {
		t.Fatal(err)
	}
	response = httptest.NewRecorder()
	server.handleStreamEvidence(response, httptest.NewRequest("GET", "/", nil))
	if response.Code != http.StatusUnprocessableEntity || !strings.Contains(response.Body.String(), "invalid artifact path") {
		t.Fatalf("linked manifest: %d %s", response.Code, response.Body.String())
	}
}

func TestInvestigationKnownForeignSessionSelection(t *testing.T) {
	active, foreign := t.TempDir(), t.TempDir()
	manager := NewSessionManager(10, 60, 10)
	manager.AddSession(&SessionInfo{SessionID: "active", IP: "192.0.2.1", InputFile: "active.pcap", OutputDir: active, Status: StatusCompleted})
	manager.AddSession(&SessionInfo{SessionID: "foreign", IP: "192.0.2.2", InputFile: "foreign.pcap", OutputDir: foreign, Status: StatusCompleted})
	s := &Server{outDir: active, isServiceMode: true, currentSession: "active", sessionManager: manager}
	var streamID string
	for dir, marker := range map[string]string{active: "active-only", foreign: "foreign-only"} {
		stream, err := streamutils.SaveStreamEvidence(dir, "TCP", core.DataFragments{&core.StreamData{RawData: []byte(marker)}}, marker, time.Unix(1, 0), "")
		if err != nil {
			t.Fatal(err)
		}
		if dir == foreign {
			streamID = filepath.Base(stream)
		}
	}
	// The owner can select another session without changing global state.
	response := httptest.NewRecorder()
	ownerRequest := func(url string) *http.Request {
		r := httptest.NewRequest("GET", url, nil)
		r.RemoteAddr = "192.0.2.2:42460"
		return r
	}
	s.handleStreamEvidence(response, ownerRequest("/?sessionId=foreign"))
	if response.Code != 200 || !strings.Contains(response.Body.String(), "foreign-only") || strings.Contains(response.Body.String(), "active-only") {
		t.Fatalf("foreign listing mixed with active evidence: %d %s", response.Code, response.Body)
	}
	response = httptest.NewRecorder()
	s.handleStreamEvidence(response, ownerRequest("/?sessionId=foreign&id="+streamID+"&direction=client"))
	if response.Code != 200 || !bytes.Equal(response.Body.Bytes(), []byte("foreign-only")) {
		t.Fatalf("foreign download mixed with active evidence: %d %s", response.Code, response.Body)
	}
	for _, selector := range []string{"sessionId=missing", "sessionId=foreign&sessionId=active", "inputFile=missing.pcap"} {
		response = httptest.NewRecorder()
		s.handleStreamEvidence(response, httptest.NewRequest("GET", "/?"+selector, nil))
		if response.Code != http.StatusServiceUnavailable || strings.Contains(response.Body.String(), "active-only") {
			t.Fatalf("invalid selector fell back: %s: %d %s", selector, response.Code, response.Body)
		}
	}
	request := httptest.NewRequest("POST", "/api/set-directory", strings.NewReader(`{"inputFile":"foreign.pcap"}`))
	request.RemoteAddr = "192.0.2.1:42460"
	response = httptest.NewRecorder()
	s.handleSetDirectory(response, request)
	if response.Code != http.StatusNotFound || s.currentSession != "active" || s.outDir != active {
		t.Fatalf("foreign session changed shared active state: %d %s", response.Code, response.Body)
	}
	if err := os.Remove(filepath.Join(foreign, "stream-evidence", streamID, "manifest.json")); err != nil {
		t.Fatal(err)
	}
	response = httptest.NewRecorder()
	s.handleStreamEvidence(response, ownerRequest("/?sessionId=foreign"))
	if response.Code != http.StatusUnprocessableEntity || !strings.Contains(response.Body.String(), "Incomplete stream evidence:") {
		t.Fatalf("missing manifest became empty/active listing: %d %s", response.Code, response.Body)
	}
}
