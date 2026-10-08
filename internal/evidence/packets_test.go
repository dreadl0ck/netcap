package evidence

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
)

func TestPacketEvidencePreservesInterfacesSectionsAndHashes(t *testing.T) {
	var source bytes.Buffer
	base := int64(1700000000000000000)
	for section := range 2 {
		intf := pcapgo.DefaultNgInterface
		intf.Name, intf.Description, intf.SnapLength, intf.LinkType = "ethernet", "fixture sensor", 128, layers.LinkTypeEthernet
		w, err := pcapgo.NewNgWriterInterface(&source, intf, pcapgo.DefaultNgWriterOptions)
		if err != nil {
			t.Fatal(err)
		}
		raw := intf
		raw.Name, raw.LinkType = "raw", layers.LinkTypeRaw
		if _, err := w.AddInterface(raw); err != nil {
			t.Fatal(err)
		}
		for i := range 3 {
			data := bytes.Repeat([]byte{byte(section*3 + i)}, 20)
			if err := w.WritePacket(gopacket.CaptureInfo{Timestamp: time.Unix(0, base+int64(section*3+i)), InterfaceIndex: i % 2, CaptureLength: 20, Length: 40}, data); err != nil {
				t.Fatal(err)
			}
		}
		if err := w.Flush(); err != nil {
			t.Fatal(err)
		}
	}
	path := filepath.Join(t.TempDir(), "input.pcapng")
	if err := os.WriteFile(path, source.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	start, end := base+1, base+4
	var output bytes.Buffer
	m, err := ExportPackets(context.Background(), path, &output, Selection{BPF: "len >= 0", StartNs: &start, EndNs: &end, MaxPackets: 10})
	if err != nil {
		t.Fatal(err)
	}
	if m.SourcePackets != 6 || m.Selected != 4 || len(m.Interfaces) != 4 || len(m.PacketSpans) != 1 || m.PacketSpans[0] != (PacketSpan{First: 2, Last: 5}) {
		t.Fatalf("manifest: %+v", m)
	}
	if m.SourceTruncatedPackets != 6 || m.SelectedTruncatedPackets != 4 {
		t.Fatalf("capture truncation hidden: %+v", m)
	}
	sourceHash, outputHash := sha256.Sum256(source.Bytes()), sha256.Sum256(output.Bytes())
	if m.SourceSHA256 != hex.EncodeToString(sourceHash[:]) || m.OutputSHA256 != hex.EncodeToString(outputHash[:]) {
		t.Fatal("hash does not identify actual capture bytes")
	}
	r, err := pcapgo.NewNgReader(bytes.NewReader(output.Bytes()), pcapgo.NgReaderOptions{WantMixedLinkType: true})
	if err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= 4; i++ {
		data, ci, err := r.ReadPacketData()
		if err != nil {
			t.Fatal(err)
		}
		if ci.Timestamp.UnixNano() != base+int64(i) || ci.Length != 40 || ci.CaptureLength != 20 || !bytes.Equal(data, bytes.Repeat([]byte{byte(i)}, 20)) {
			t.Fatalf("packet %d changed: %+v %x", i, ci, data)
		}
		intf, err := r.Interface(ci.InterfaceIndex)
		if err != nil {
			t.Fatal(err)
		}
		wantLink := layers.LinkTypeEthernet
		if i == 1 || i == 4 {
			wantLink = layers.LinkTypeRaw
		}
		if intf.LinkType != wantLink || intf.Description != "fixture sensor" || intf.SnapLength != 128 || intf.TimestampResolution != 9 {
			t.Fatalf("interface lost: %+v", intf)
		}
	}
	if _, _, err := r.ReadPacketData(); err != io.EOF {
		t.Fatalf("extra data: %v", err)
	}
}

func TestPacketEvidenceRejectsOversizedCaptureDeclarations(t *testing.T) {
	var source bytes.Buffer
	w, err := pcapgo.NewNgWriter(&source, layers.LinkTypeEthernet)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.WritePacket(gopacket.CaptureInfo{Timestamp: time.Unix(1, 2), CaptureLength: 14, Length: 14}, make([]byte, 14)); err != nil {
		t.Fatal(err)
	}
	if err := w.Flush(); err != nil {
		t.Fatal(err)
	}
	packetOffset := -1
	for offset := 0; offset+8 <= source.Len(); {
		kind, size := binary.LittleEndian.Uint32(source.Bytes()[offset:]), binary.LittleEndian.Uint32(source.Bytes()[offset+4:])
		if kind == 6 {
			packetOffset = offset
			break
		}
		if size < 12 {
			t.Fatal("invalid generated fixture")
		}
		offset += int(size)
	}
	if packetOffset < 0 {
		t.Fatal("missing generated packet block")
	}
	for _, tc := range []struct {
		name   string
		mutate func([]byte)
	}{
		{"packet-length", func(data []byte) {
			binary.LittleEndian.PutUint32(data[packetOffset+20:], 0xffffffff)
			binary.LittleEndian.PutUint32(data[packetOffset+24:], 0xffffffff)
		}},
		{"block-length", func(data []byte) { binary.LittleEndian.PutUint32(data[packetOffset+4:], maxCaptureBlock+4) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data := append([]byte(nil), source.Bytes()...)
			tc.mutate(data)
			path := filepath.Join(t.TempDir(), "invalid.pcapng")
			if err := os.WriteFile(path, data, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := ExportPackets(context.Background(), path, io.Discard, Selection{BPF: "len >= 0", MaxPackets: 10}); err == nil || !strings.Contains(err.Error(), "oversized") {
				t.Fatalf("oversized declaration reached allocation: %v", err)
			}
		})
	}
}

func TestPacketEvidenceRejectsPartialAndOverBudgetExports(t *testing.T) {
	var source bytes.Buffer
	w := pcapgo.NewWriterNanos(&source)
	if err := w.WriteFileHeader(64, layers.LinkTypeEthernet); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := w.WritePacket(gopacket.CaptureInfo{Timestamp: time.Unix(1, 2), CaptureLength: 14, Length: 14}, make([]byte, 14)); err != nil {
			t.Fatal(err)
		}
	}
	path := filepath.Join(t.TempDir(), "input.pcap")
	if err := os.WriteFile(path, source.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name      string
		selection Selection
	}{
		{"limit", Selection{BPF: "len >= 0", MaxPackets: 1}},
		{"invalid-bpf", Selection{BPF: "not a bpf expression", MaxPackets: 10}},
		{"missing-limit", Selection{BPF: "len >= 0"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ExportPackets(context.Background(), path, io.Discard, tc.selection); err == nil {
				t.Fatal("qualified invalid/partial export")
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := ExportPackets(ctx, path, io.Discard, Selection{BPF: "len >= 0", MaxPackets: 10}); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation: %v", err)
	}
	if err := os.WriteFile(path, source.Bytes()[:source.Len()-1], 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := ExportPackets(context.Background(), path, io.Discard, Selection{BPF: "len >= 0", MaxPackets: 10}); err == nil {
		t.Fatal("qualified truncated capture")
	}
}
