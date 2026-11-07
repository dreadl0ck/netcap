package collector

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/dreadl0ck/netcap/internal/evidence"
	"github.com/dreadl0ck/netcap/types"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
)

func TestCaptureInputSynthetic(t *testing.T) {
	le := binary.LittleEndian
	frame := rawPacketFixture(t, false, 64)
	pcap := inputPCAPHeader(le, false, 1, 1)
	pcap = append(pcap, inputPCAPRecord(le, 123, 0, 64, 64, frame)...)
	bad := inputPCAPRecord(le, 124, 0, 64, 63, frame)
	last := inputPCAPRecord(le, 125, 0, 64, 64, frame)
	ng := append(inputNGSection(le), inputNGInterface(le, 1, 1)...)
	ng = append(ng, inputNGPacket(le, 0, 64, 64, frame)...)
	ngBad := inputNGPacket(le, 0, 100, 100, frame)
	ngLast := inputNGPacket(le, 0, 64, 64, frame)
	for _, tc := range []struct {
		name             string
		data             []byte
		ng               bool
		packets, skipped int64
		eof              bool
	}{
		{"pcap-recover", append(append(bytes.Clone(pcap), bad...), last...), false, 2, 1, true},
		{"pcap-truncated", append(bytes.Clone(pcap), last[:23]...), false, 1, 0, false},
		{"pcap-short-header", append(bytes.Clone(pcap), last[:7]...), false, 1, 0, false},
		{"ng-recover", append(append(bytes.Clone(ng), ngBad...), ngLast...), true, 2, 1, true},
		{"ng-truncated", append(bytes.Clone(ng), ngLast[:29]...), true, 1, 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			if saved := os.Getenv("NETCAP_INPUT_RESULTS"); saved != "" {
				root = filepath.Join(saved, "synthetic-"+tc.name)
				if err := os.MkdirAll(root, 0700); err != nil {
					t.Fatal(err)
				}
			}
			input := filepath.Join(root, "input.pcap")
			if tc.ng {
				input += "ng"
			}
			if err := os.WriteFile(input, tc.data, 0600); err != nil {
				t.Fatal(err)
			}
			for _, workers := range []int{1, 4} {
				out := filepath.Join(root, fmt.Sprintf("w%d", workers))
				result := runInputRepro(t, input, out, workers)
				var report CaptureInputReport
				readInputJSON(t, filepath.Join(out, "capture-input.json"), &report)
				if result.Packets != uint64(tc.packets) || result.Error == "" || report.Status != "partial" || report.CountedPackets != tc.packets || report.ProcessedPackets != tc.packets || report.SkippedRecords != tc.skipped || report.ReachedEOF != tc.eof {
					t.Fatalf("%+v %+v", result, report)
				}
				records := bookRecords(t, out, "UDP", func() *types.UDP { return &types.UDP{} })
				if int64(len(records)) != tc.packets {
					t.Fatalf("valid-prefix UDP output lost: %d", len(records))
				}
				var capture evidence.CaptureManifest
				readInputJSON(t, filepath.Join(out, "capture-manifest.json"), &capture)
				if capture.Status != "error" || capture.Error == "" || capture.IngressPackets != uint64(tc.packets) {
					t.Fatalf("false complete capture: %+v", capture)
				}
				t.Logf("workers=%d processed=%d skipped=%d eof=%t output=%s", workers, report.ProcessedPackets, report.SkippedRecords, report.ReachedEOF, out)
			}
		})
	}
}

func TestCaptureInputMixedInterfaces(t *testing.T) {
	le := binary.LittleEndian
	eth := rawPacketFixture(t, false, 64)
	frames := [][]byte{eth, inputNFLOG(le, 2, eth[14:]), append([]byte{15, 0, 8, 0}, eth[14:]...), inputSLL2(eth[14:]), {2, 0, 5}, {1, 0, 6, 0x45}, inputSLL2(eth[14:])}
	links := []layers.LinkType{1, 239, 104, 276, 230, 230, 275}
	input := inputNGSection(le)
	for _, lt := range links {
		input = append(input, inputNGInterface(le, lt, 1)...)
	}
	for i, frame := range frames {
		input = append(input, inputNGPacket(le, uint32(i), uint32(len(frame)), uint32(len(frame)), frame)...)
	}
	input = append(input, inputNGSection(le)...)
	input = append(input, inputNGInterface(le, 1, 65535)...)
	input = append(input, inputNGPacket(le, 0, uint32(len(eth)), uint32(len(eth)), eth)...)
	frames = append(frames, eth)
	links = append(links, 1)
	root := t.TempDir()
	if saved := os.Getenv("NETCAP_INPUT_RESULTS"); saved != "" {
		root = filepath.Join(saved, "synthetic-mixed")
		if err := os.MkdirAll(root, 0700); err != nil {
			t.Fatal(err)
		}
	}
	path := filepath.Join(root, "input.pcapng")
	if err := os.WriteFile(path, input, 0600); err != nil {
		t.Fatal(err)
	}
	for _, workers := range []int{1, 4} {
		out := filepath.Join(root, fmt.Sprintf("w%d", workers))
		result := runInputRepro(t, path, out, workers)
		var report CaptureInputReport
		readInputJSON(t, filepath.Join(out, "capture-input.json"), &report)
		if result.Packets != 8 || result.Error == "" || report.Status != "unsupported" || report.Unsupported != 2 || report.DecodeErrors != 0 || report.CountedPackets != 8 {
			t.Fatalf("mixed: %+v %+v", result, report)
		}
		udp := bookRecords(t, out, "UDP", func() *types.UDP { return &types.UDP{} })
		if len(udp) != 5 {
			t.Fatalf("expected exactly five UDP packets, got %d", len(udp))
		}
		var capture evidence.CaptureManifest
		readInputJSON(t, filepath.Join(out, "capture-manifest.json"), &capture)
		if len(capture.Segments) != 1 || capture.Status != "error" {
			t.Fatalf("retention: %+v", capture)
		}
		f, err := os.Open(filepath.Join(out, capture.Segments[0].Name))
		if err != nil {
			t.Fatal(err)
		}
		r, err := pcapgo.NewNgReader(f, pcapgo.NgReaderOptions{WantMixedLinkType: true})
		if err != nil {
			f.Close()
			t.Fatal(err)
		}
		for i, want := range frames {
			got, ci, err := r.ReadPacketData()
			if err != nil || !bytes.Equal(got, want) || ci.InterfaceIndex != i || ci.AncillaryData[0] != links[i] || ci.Length != len(want) || ci.CaptureLength != len(want) {
				f.Close()
				t.Fatalf("retained source %d: %v %+v", i, err, ci)
			}
		}
		if _, _, err := r.ReadPacketData(); err != io.EOF {
			t.Fatal(err)
		}
		f.Close()
		t.Logf("mixed output=%s", out)
	}
}

func TestCaptureInputEmptyPacket(t *testing.T) {
	ci := gopacket.CaptureInfo{AncillaryData: []any{layers.LinkType(239)}}
	c := rawPacketCollector(1, 1, gopacket.Lazy)
	p := c.decodeRawPacketData(nil, &ci)
	if p.ErrorLayer() == nil {
		t.Fatal("empty captured frame must not become opaque success")
	}
}
