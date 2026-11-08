package webui

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/binary"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/pcapgo"
)

func TestLegacyPCAPFilterPreservesSelectionAndNanoseconds(t *testing.T) {
	path, base := observedTuplePCAP(t)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	le := binary.LittleEndian
	le.PutUint16(data[6:], 1)
	for offset := 24; offset < len(data); {
		captured := le.Uint32(data[offset+8:])
		le.PutUint32(data[offset+8:], captured+7) // pre-2.3: original length first
		le.PutUint32(data[offset+12:], captured)
		offset += 16 + int(captured)
	}
	for _, compressed := range []bool{false, true} {
		input := data
		if compressed {
			var b bytes.Buffer
			w := gzip.NewWriter(&b)
			if _, err := w.Write(data); err != nil {
				t.Fatal(err)
			}
			if err := w.Close(); err != nil {
				t.Fatal(err)
			}
			input = b.Bytes()
		}
		if err := os.WriteFile(path, input, 0600); err != nil {
			t.Fatal(err)
		}
		out := filepath.Join(t.TempDir(), "selected.pcap")
		wantTime := base.Add(time.Nanosecond)
		n, err := filterPCAPSelectionContext(context.Background(), path, "tcp port 9243", out, func(ci gopacket.CaptureInfo) bool { return ci.Timestamp.Equal(wantTime) })
		if err != nil || n != 1 {
			t.Fatalf("gzip=%t: count=%d err=%v", compressed, n, err)
		}
		f, err := os.Open(out)
		if err != nil {
			t.Fatal(err)
		}
		r, err := pcapgo.NewReader(f)
		if err != nil {
			f.Close()
			t.Fatal(err)
		}
		packet, ci, err := r.ReadPacketData()
		if err != nil || !ci.Timestamp.Equal(wantTime) || ci.Length != len(packet)+7 || ci.CaptureLength != len(packet) {
			f.Close()
			t.Fatalf("selected metadata=%+v err=%v", ci, err)
		}
		if _, _, err := r.ReadPacketData(); err != io.EOF {
			f.Close()
			t.Fatalf("extra output: %v", err)
		}
		f.Close()
	}
}
