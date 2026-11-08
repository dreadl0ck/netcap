package split

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/internal/evidence"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
)

func TestBoundedSplitCommand(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "source.pcap")
	f, err := os.Create(input)
	if err != nil {
		t.Fatal(err)
	}
	w := pcapgo.NewWriterNanos(f)
	if err := w.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= 3; i++ {
		data := bytes.Repeat([]byte{byte(i)}, 60)
		if err := w.WritePacket(gopacket.CaptureInfo{Timestamp: time.Unix(0, int64(i)), CaptureLength: 60, Length: 80}, data); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(input)
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(before)
	run := func(ctx context.Context, out string, args ...string) error {
		cmd := GetCommand()
		cmd.Writer = io.Discard
		return cmd.Run(ctx, append([]string{"split", "--read", input, "--out", out}, args...))
	}
	t.Run("exact inclusive nanos and provenance", func(t *testing.T) {
		out := filepath.Join(dir, "selected")
		if err := run(context.Background(), out, "--start-ns", "2", "--end-ns", "2", "--source-sha256", hex.EncodeToString(hash[:])); err != nil {
			t.Fatal(err)
		}
		b, err := os.ReadFile(filepath.Join(out, "packet-selection.json"))
		if err != nil {
			t.Fatal(err)
		}
		var manifest evidence.PacketManifest
		if err := json.Unmarshal(b, &manifest); err != nil {
			t.Fatal(err)
		}
		if manifest.SourcePackets != 3 || manifest.Selected != 1 || manifest.SelectedTruncatedPackets != 1 || manifest.SourceSHA256 != hex.EncodeToString(hash[:]) {
			t.Fatalf("manifest: %+v", manifest)
		}
		data, err := os.ReadFile(filepath.Join(out, "selected.pcapng"))
		if err != nil {
			t.Fatal(err)
		}
		outputHash := sha256.Sum256(data)
		if manifest.OutputSHA256 != hex.EncodeToString(outputHash[:]) {
			t.Fatal("output hash mismatch")
		}
		r, err := pcapgo.NewNgReader(bytes.NewReader(data), pcapgo.DefaultNgReaderOptions)
		if err != nil {
			t.Fatal(err)
		}
		packet, ci, err := r.ReadPacketData()
		if err != nil || !bytes.Equal(packet, bytes.Repeat([]byte{2}, 60)) || ci.Timestamp.UnixNano() != 2 || ci.Length != 80 {
			t.Fatalf("packet differs: %+v %v", ci, err)
		}
		if _, _, err := r.ReadPacketData(); err != io.EOF {
			t.Fatalf("extra packet: %v", err)
		}
		if err := run(context.Background(), out, "--bpf", "len >= 0"); err == nil {
			t.Fatal("overwrote prior output")
		}
	})
	for name, args := range map[string][]string{
		"packet limit":     {"--bpf", "len >= 0", "--max-packets", "1"},
		"byte limit":       {"--bpf", "len >= 0", "--max-bytes", "1"},
		"invalid filter":   {"--bpf", "invalid ["},
		"no matches":       {"--start-ns", "4", "--end-ns", "5"},
		"unpaired time":    {"--start-ns", "1"},
		"reversed time":    {"--start-ns", "3", "--end-ns", "1"},
		"changed source":   {"--bpf", "len >= 0", "--source-sha256", "bad"},
		"missing selector": {},
	} {
		t.Run(name, func(t *testing.T) {
			out := filepath.Join(t.TempDir(), "out")
			if err := run(context.Background(), out, args...); err == nil {
				t.Fatal("expected refusal")
			}
			if _, err := os.Stat(out); !os.IsNotExist(err) {
				t.Fatal("failed export left output")
			}
		})
	}
	t.Run("canceled", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		out := filepath.Join(t.TempDir(), "out")
		if err := run(ctx, out, "--bpf", "len >= 0"); err == nil {
			t.Fatal("accepted cancellation")
		}
		if _, err := os.Stat(out); !os.IsNotExist(err) {
			t.Fatal("cancellation left output")
		}
	})
	after, err := os.ReadFile(input)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("source changed")
	}
}
