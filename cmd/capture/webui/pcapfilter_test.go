package webui

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
)

func TestPacketExportNanosecondsAndSelection(t *testing.T) {
	dir := t.TempDir()
	input, output := filepath.Join(dir, "input.pcap"), filepath.Join(dir, "output.pcap")
	f, err := os.Create(input)
	if err != nil {
		t.Fatal(err)
	}
	w := pcapgo.NewWriterNanos(f)
	if err := w.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
		t.Fatal(err)
	}
	data := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 8, 0}
	base := int64(1700000000000000000)
	for delta := int64(1); delta <= 3; delta++ {
		if err := w.WritePacket(gopacket.CaptureInfo{Timestamp: time.Unix(0, base+delta), CaptureLength: len(data), Length: len(data) + 10}, data); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	start, end := base+2, base+2
	selection := connectionPacketSelection{start: &start, end: &end}
	count, err := filterPCAPSelectionContext(context.Background(), input, "len >= 0", output, selection.contains)
	if err != nil || count != 1 {
		t.Fatalf("export count=%d error=%v", count, err)
	}
	out, err := os.Open(output)
	if err != nil {
		t.Fatal(err)
	}
	defer out.Close()
	r, err := pcapgo.NewReader(out)
	if err != nil {
		t.Fatal(err)
	}
	got, ci, err := r.ReadPacketData()
	if err != nil {
		t.Fatal(err)
	}
	if ci.Timestamp.UnixNano() != base+2 || string(got) != string(data) || ci.CaptureLength != len(data) || ci.Length != len(data)+10 {
		t.Fatalf("export changed packet evidence: %v, %x", ci, got)
	}
	if _, _, err := r.ReadPacketData(); err != io.EOF {
		t.Fatalf("expected EOF: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := filterPCAPToFileContext(ctx, input, "len >= 0", output); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel: %v", err)
	}
	if _, err := os.Stat(output); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("partial artifact retained: %v", err)
	}
}
