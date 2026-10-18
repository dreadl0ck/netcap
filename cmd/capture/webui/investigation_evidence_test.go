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
	// Session IDs are shareable read selectors; selection must not change global state.
	response := httptest.NewRecorder()
	s.handleStreamEvidence(response, httptest.NewRequest("GET", "/?sessionId=foreign", nil))
	if response.Code != 200 || !strings.Contains(response.Body.String(), "foreign-only") || strings.Contains(response.Body.String(), "active-only") {
		t.Fatalf("foreign listing mixed with active evidence: %d %s", response.Code, response.Body)
	}
	response = httptest.NewRecorder()
	s.handleStreamEvidence(response, httptest.NewRequest("GET", "/?sessionId=foreign&id="+streamID+"&direction=client", nil))
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
	s.handleStreamEvidence(response, httptest.NewRequest("GET", "/?sessionId=foreign", nil))
	if response.Code != http.StatusUnprocessableEntity || !strings.Contains(response.Body.String(), "Incomplete stream evidence:") {
		t.Fatalf("missing manifest became empty/active listing: %d %s", response.Code, response.Body)
	}
}
