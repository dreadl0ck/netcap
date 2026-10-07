package webui

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/internal/evidence"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
)

func TestConnectionEvidenceArchiveContainsVerifiableCapture(t *testing.T) {
	var source bytes.Buffer
	w := pcapgo.NewWriterNanos(&source)
	if err := w.WriteFileHeader(128, layers.LinkTypeEthernet); err != nil {
		t.Fatal(err)
	}
	if err := w.WritePacket(gopacket.CaptureInfo{Timestamp: time.Unix(1700000000, 3), CaptureLength: 14, Length: 14}, make([]byte, 14)); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "fixture.pcap")
	if err := os.WriteFile(path, source.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	serveConnectionEvidence(recorder, httptest.NewRequest(http.MethodGet, "/", nil), path, connectionPacketSelection{bpf: "len >= 0"})
	if recorder.Code != http.StatusOK || recorder.Header().Get("Content-Type") != "application/zip" {
		t.Fatalf("response %d: %s", recorder.Code, recorder.Body)
	}
	r, err := zip.NewReader(bytes.NewReader(recorder.Body.Bytes()), int64(recorder.Body.Len()))
	if err != nil {
		t.Fatal(err)
	}
	if len(r.File) != 2 {
		t.Fatalf("entries=%d", len(r.File))
	}
	var manifest evidence.PacketManifest
	var packets []byte
	for _, entry := range r.File {
		f, err := entry.Open()
		if err != nil {
			t.Fatal(err)
		}
		data, err := io.ReadAll(f)
		f.Close()
		if err != nil {
			t.Fatal(err)
		}
		switch entry.Name {
		case "manifest.json":
			if err := json.Unmarshal(data, &manifest); err != nil {
				t.Fatal(err)
			}
		case "packets.pcapng":
			packets = data
		default:
			t.Fatalf("unexpected entry: %s", entry.Name)
		}
	}
	inputHash, outputHash := sha256.Sum256(source.Bytes()), sha256.Sum256(packets)
	if manifest.SourceSHA256 != hex.EncodeToString(inputHash[:]) || manifest.OutputSHA256 != hex.EncodeToString(outputHash[:]) || manifest.Selected != 1 || len(manifest.Limitations) == 0 {
		t.Fatalf("manifest does not verify the archived input/output: %+v", manifest)
	}
	if recorder.Header().Get("X-Netcap-Source-SHA256") != manifest.SourceSHA256 {
		t.Fatal("header hash differs from archived manifest")
	}

	empty := httptest.NewRecorder()
	serveConnectionEvidence(empty, httptest.NewRequest(http.MethodGet, "/", nil), path, connectionPacketSelection{bpf: "len > 1000"})
	if empty.Code != http.StatusNotFound {
		t.Fatalf("empty selection: %d", empty.Code)
	}
	if err := os.WriteFile(path, source.Bytes()[:source.Len()-1], 0600); err != nil {
		t.Fatal(err)
	}
	partial := httptest.NewRecorder()
	serveConnectionEvidence(partial, httptest.NewRequest(http.MethodGet, "/", nil), path, connectionPacketSelection{bpf: "len >= 0"})
	if partial.Code != http.StatusInternalServerError || partial.Header().Get("Content-Type") == "application/zip" {
		t.Fatalf("served partial evidence: %d", partial.Code)
	}
}
