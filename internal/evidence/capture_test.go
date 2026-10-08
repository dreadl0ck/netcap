package evidence

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
)

func TestCaptureManifestInputHealthAndRetentionExpiry(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(t.TempDir(), "original.pcap")
	body := []byte("original capture identity fixture")
	if err := os.WriteFile(input, body, 0600); err != nil {
		t.Fatal(err)
	}
	c, err := NewCapture(context.Background(), dir, CaptureConfig{Kind: "file", Source: input, Workers: 2, RetainPackets: true, SegmentBytes: 1 << 20, RetentionBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	packet := make([]byte, 600<<10)
	for i := 0; i < 3; i++ {
		ci := gopacket.CaptureInfo{Timestamp: time.Unix(1, int64(i+1)), CaptureLength: len(packet), Length: len(packet) + 1}
		if err := c.Observe(packet, ci, layers.LinkTypeEthernet); err != nil {
			t.Fatal(err)
		}
	}
	if err := c.Close("done", 2, 1, nil); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "capture-manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var m CaptureManifest
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(body)
	if m.InputSHA256 != hex.EncodeToString(hash[:]) || m.Status != "partial" || m.IngressPackets != 3 || m.AdmittedPackets != 2 || m.QueueDrops != 1 || m.KernelDrops != nil || m.TruncatedPackets != 3 || len(m.Segments) != 3 {
		t.Fatalf("manifest: %+v", m)
	}
	for i, segment := range m.Segments {
		path := filepath.Join(dir, segment.Name)
		if i < 2 {
			if segment.State != "expired" {
				t.Fatal("expired coverage hidden")
			}
			if _, err := os.Stat(path); !os.IsNotExist(err) {
				t.Fatal("expired packet file still present")
			}
		} else {
			file, err := os.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer file.Close()
			reader, err := pcapgo.NewNgReader(file, pcapgo.DefaultNgReaderOptions)
			if err != nil {
				t.Fatal(err)
			}
			data, ci, err := reader.ReadPacketData()
			if err != nil || len(data) != len(packet) || ci.Timestamp.UnixNano() != 1000000003 || ci.Length != len(packet)+1 {
				t.Fatalf("retained bytes/time changed: %v", err)
			}
			bytes, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			digest := sha256.Sum256(bytes)
			if segment.SHA256 != hex.EncodeToString(digest[:]) {
				t.Fatal("segment hash does not identify retained bytes")
			}
		}
	}
	if _, err := NewCapture(context.Background(), dir, CaptureConfig{Kind: "file", Source: input}); err == nil {
		t.Fatal("existing provenance replaced")
	}
}

func TestCaptureKernelUnavailableAndStorageError(t *testing.T) {
	dir := t.TempDir()
	c, err := NewCapture(context.Background(), dir, CaptureConfig{Kind: "live", Source: "fixture0", RetainPackets: true, SegmentBytes: 1 << 20, RetentionBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "retained-packets"), []byte("block directory"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := c.Observe([]byte{1, 2, 3}, gopacket.CaptureInfo{Timestamp: time.Unix(1, 0), CaptureLength: 3, Length: 3}, layers.LinkTypeEthernet); err == nil {
		t.Fatal("storage failure ignored")
	}
	if err := c.Close("stopped", 1, 0, nil); err == nil {
		t.Fatal("failed retention reported as success")
	}
	data, err := os.ReadFile(filepath.Join(dir, "capture-manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var m CaptureManifest
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	if m.Status != "error" || m.Error == "" || m.KernelReceived != nil {
		t.Fatal("unavailable kernel/storage evidence fabricated")
	}
}
