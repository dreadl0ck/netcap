package collector

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dreadl0ck/netcap/internal/evidence"
	"github.com/dreadl0ck/netcap/types"
)

func TestBitTorrentPeerHandshakeDoesNotEmitProtobufByDefault(t *testing.T) {
	wire, input := newBookCapture(t)
	header := "\x13BitTorrent protocol" + strings.Repeat("\x00", 8) + strings.Repeat("\x11", 20)
	wire.conversation("192.0.2.1", "198.51.100.1", 42000, 6881, false,
		bookMessage{text: header + strings.Repeat("\x22", 20)},
		bookMessage{server: true, text: header + strings.Repeat("\x33", 20)})
	out := t.TempDir()
	cfg := ultimateCaptureConfig(out, 1, 0)
	cfg.CaptureEvidence = true
	if err := New(cfg).CollectPcap(input); err != nil {
		t.Fatal(err)
	}
	manifest := bookJSON[evidence.CaptureManifest](t, filepath.Join(out, "capture-manifest.json"))
	if manifest.Status != "done" || manifest.AdmittedPackets != 8 {
		t.Fatalf("incomplete fixture capture: status=%q packets=%d", manifest.Status, manifest.AdmittedPackets)
	}
	connections := bookRecords(t, out, "Connection", func() *types.Connection { return new(types.Connection) })
	if len(connections) != 1 {
		t.Fatalf("expected one reconstructed connection, got %d", len(connections))
	}
	for _, name := range []string{"Protobuf.ncap", "Protobuf.ncap.gz"} {
		if _, err := os.Stat(filepath.Join(out, name)); !os.IsNotExist(err) {
			t.Fatalf("unexpected Protobuf audit %s: %v", name, err)
		}
	}
}
