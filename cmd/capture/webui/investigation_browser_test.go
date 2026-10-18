//go:build !appstore

package webui

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/internal/decoder/core"
	streamutils "github.com/dreadl0ck/netcap/internal/decoder/stream/utils"
	"github.com/dreadl0ck/netcap/internal/evidence"
	"github.com/dreadl0ck/netcap/internal/reassembly"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
)

func TestInvestigationBrowserPersistence(t *testing.T) {
	if os.Getenv("NETCAP_INVESTIGATION_BROWSER") != "1" {
		t.Skip("requires built frontend and Playwright Chromium; NETCAP_INVESTIGATION_BROWSER=1")
	}
	isolateBrowserFixture(t)
	dir := t.TempDir()
	payload := []byte{0, 255, 27, '<', 's', '>', '\r', '\n', 128}
	ip := &layers.IPv4{Version: 4, TTL: 64, SrcIP: []byte{192, 0, 2, 1}, DstIP: []byte{192, 0, 2, 2}, Protocol: layers.IPProtocolTCP}
	tcp := &layers.TCP{SrcPort: 50000, DstPort: 443, Seq: 1, ACK: true}
	if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatal(err)
	}
	buffer := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, ip, tcp, gopacket.Payload(payload)); err != nil {
		t.Fatal(err)
	}
	var source bytes.Buffer
	writer := pcapgo.NewWriterNanos(&source)
	if err := writer.WriteFileHeader(65535, layers.LinkTypeIPv4); err != nil {
		t.Fatal(err)
	}
	ci := gopacket.CaptureInfo{Timestamp: time.Unix(1700000000, 3), CaptureLength: len(buffer.Bytes()), Length: len(buffer.Bytes())}
	if err := writer.WritePacket(ci, buffer.Bytes()); err != nil {
		t.Fatal(err)
	}
	input := filepath.Join(dir, "selected.pcap")
	if err := os.WriteFile(input, source.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	// Replay a real synthetic PCAP through the persistence writers, not a live interface.
	reader, err := pcapgo.NewReader(bytes.NewReader(source.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	data, info, err := reader.ReadPacketData()
	if err != nil {
		t.Fatal(err)
	}
	capture, err := evidence.NewCapture(context.Background(), dir, evidence.CaptureConfig{Kind: "file", Source: input})
	if err != nil {
		t.Fatal(err)
	}
	if err := capture.Observe(data, info, reader.LinkType()); err != nil {
		t.Fatal(err)
	}
	if err := capture.Close("completed", 1, 0, nil); err != nil {
		t.Fatal(err)
	}
	packet := gopacket.NewPacket(data, layers.LayerTypeIPv4, gopacket.Default)
	stream, err := streamutils.SaveStreamEvidence(dir, "TCP", core.DataFragments{&core.StreamData{RawData: packet.ApplicationLayer().Payload(), Dir: reassembly.TCPDirClientToServer}}, "synthetic-pcap", info.Timestamp, "fixture-community")
	if err != nil {
		t.Fatal(err)
	}
	emptyInput, unavailableInput := filepath.Join(dir, "empty.pcap"), filepath.Join(dir, "unavailable.pcap")
	empty, unavailable := t.TempDir(), t.TempDir()
	for _, path := range []string{emptyInput, unavailableInput} {
		if err := os.WriteFile(path, source.Bytes(), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir(filepath.Join(empty, "stream-evidence"), 0700); err != nil {
		t.Fatal(err)
	}
	server := NewServer("127.0.0.1:0", dir, []string{input, emptyInput, unavailableInput}, "", false, false, false, nil, nil, false)
	for input, output := range map[string]string{input: dir, emptyInput: empty, unavailableInput: unavailable} {
		server.SetFileOutputDir(input, output)
		server.completedFiles[input] = true
	}
	server.outDir = dir
	server.activeInputFile = input
	server.isProcessing = false
	if err := server.Start(); err != nil {
		t.Fatal(err)
	}
	defer server.Stop(context.Background())
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "node", "scripts/qualify-investigation.mjs", server.GetURL(), filepath.Base(stream), fmt.Sprintf("%x", sha256.Sum256(source.Bytes())))
	command.Dir = "frontend"
	command.Env = browserFixtureEnvironment(t, dir)
	output, err := command.CombinedOutput()
	t.Log(string(output))
	if err != nil {
		t.Fatal(err)
	}
	stored, err := os.ReadFile(filepath.Join(stream, "client.bin"))
	if err != nil || !bytes.Equal(stored, payload) {
		t.Fatalf("browser changed persisted stream: %x, %v", stored, err)
	}
}
