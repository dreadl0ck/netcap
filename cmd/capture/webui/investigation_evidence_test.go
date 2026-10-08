package webui

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
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
