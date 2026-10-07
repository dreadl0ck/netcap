package utils

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/internal/decoder/core"
	"github.com/dreadl0ck/netcap/internal/reassembly"
	"github.com/gopacket/gopacket"
)

func TestStreamEvidenceBytesGapsAndTupleReuse(t *testing.T) {
	payload := make([]byte, 256)
	for i := range payload {
		payload[i] = byte(i)
	}
	payload = append(payload, []byte("\x1b[31mclient-looking bytes\x1b[0m")...)
	fragments := core.DataFragments{
		&core.StreamData{RawData: payload[:100], Dir: reassembly.TCPDirClientToServer, CaptureInformation: gopacket.CaptureInfo{Timestamp: time.Unix(1, 3)}},
		&core.StreamData{RawData: []byte("response"), Dir: reassembly.TCPDirServerToClient, CaptureInformation: gopacket.CaptureInfo{Timestamp: time.Unix(1, 4)}},
		&core.StreamData{Dir: reassembly.TCPDirClientToServer, SkippedBytes: 42, CaptureInformation: gopacket.CaptureInfo{Timestamp: time.Unix(1, 1)}},
		&core.StreamData{RawData: payload[100:], Dir: reassembly.TCPDirClientToServer, CaptureInformation: gopacket.CaptureInfo{Timestamp: time.Unix(1, 2)}},
	}
	out := t.TempDir()
	first, err := SaveStreamEvidence(out, "TCP", fragments, "same-tuple", time.Unix(1, 1), "community")
	if err != nil {
		t.Fatal(err)
	}
	second, err := SaveStreamEvidence(out, "TCP", fragments, "same-tuple", time.Unix(1, 1), "community")
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("tuple reuse appended evidence")
	}
	data, err := os.ReadFile(filepath.Join(first, "client.bin"))
	if err != nil || !bytes.Equal(data, payload) {
		t.Fatalf("payload altered: %v", err)
	}
	data, err = os.ReadFile(filepath.Join(first, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest StreamEvidenceManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(payload)
	if manifest.Client.SHA256 != hex.EncodeToString(hash[:]) || manifest.Status != "gapped" || manifest.Spans[2].MissingBytes != 42 || manifest.Spans[3].Offset != 100 || manifest.Spans[3].TimestampNs != "1000000002" {
		t.Fatalf("gap/offset evidence lost: %+v", manifest)
	}
}

func TestStreamEvidenceUDPPreservesDatagramBoundaries(t *testing.T) {
	forward := gopacket.NewFlow(gopacket.EndpointType(4), []byte{1, 2}, []byte{3, 4})
	fragments := core.DataFragments{&core.StreamData{RawData: []byte("one"), Trans: forward}, &core.StreamData{RawData: []byte("two"), Trans: forward.Reverse()}, &core.StreamData{RawData: []byte("three"), Trans: forward}}
	dir, err := SaveStreamEvidence(t.TempDir(), "UDP", fragments, "udp", time.Unix(1, 0), "")
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var m StreamEvidenceManifest
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	if len(m.Spans) != 3 || !m.Spans[0].Datagram || m.Spans[1].Direction != "server" || m.Spans[2].Offset != 3 {
		t.Fatalf("datagrams collapsed: %+v", m)
	}
}
