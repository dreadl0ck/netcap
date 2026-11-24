package collector

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/gopacket/gopacket/layers"
)

// CollectBPF used libpcap's reader: no capture-input.json, and the first
// damaged record ended the read as an error. It now shares the bounded
// reader and reports what the filter excluded.
func TestCollectBPFWritesCaptureInputReport(t *testing.T) {
	udp, tcp := rawPacketFixture(t, false, 64), rawPacketFixture(t, true, 80)
	for _, ng := range []bool{false, true} {
		var input []byte
		if ng {
			input = append(inputNGSection(binary.LittleEndian), inputNGInterface(binary.LittleEndian, layers.LinkTypeEthernet, 65535)...)
			for _, frame := range [][]byte{udp, tcp, udp, tcp, udp} {
				input = append(input, inputNGPacket(binary.LittleEndian, 0, uint32(len(frame)), uint32(len(frame)), frame)...)
			}
		} else {
			input = inputPCAPHeader(binary.LittleEndian, false, 65535, layers.LinkTypeEthernet)
			for i, frame := range [][]byte{udp, tcp, udp, tcp, udp} {
				input = append(input, inputPCAPRecord(binary.LittleEndian, uint32(100+i), 0, uint32(len(frame)), uint32(len(frame)), frame)...)
			}
			// A truncated last record keeps the valid prefix.
			input = append(input, inputPCAPRecord(binary.LittleEndian, 200, 0, 64, 64, udp)[:30]...)
		}
		path := filepath.Join(t.TempDir(), "input.pcap")
		if err := os.WriteFile(path, input, 0600); err != nil {
			t.Fatal(err)
		}
		c := lifecycleInitCollector(t)
		err := c.CollectBPF(path, "udp")
		if c.GetNumPackets() != 3 {
			t.Fatalf("ng=%v admitted %d, err %v", ng, c.GetNumPackets(), err)
		}
		raw, readErr := os.ReadFile(filepath.Join(c.outputDir(), CaptureInputFile))
		var report CaptureInputReport
		if readErr != nil || json.Unmarshal(raw, &report) != nil {
			t.Fatalf("ng=%v: no capture input report: %v", ng, readErr)
		}
		if report.BPFFilter != "udp" || report.BPFExcluded != 2 || report.ProcessedPackets != 5 || !report.Finalized {
			t.Fatalf("ng=%v report %+v", ng, report)
		}
		if !ng && (err == nil || report.Status != "partial" || report.ReachedEOF) {
			t.Fatalf("truncated tail: %v %+v", err, report)
		}
		if ng && (err != nil || report.Status != "complete") {
			t.Fatalf("ng: %v %+v", err, report)
		}
	}
	c := lifecycleInitCollector(t)
	path := filepath.Join(t.TempDir(), "input.pcap")
	if err := os.WriteFile(path, bytes.Clone(inputPCAPHeader(binary.LittleEndian, false, 65535, layers.LinkTypeEthernet)), 0600); err != nil {
		t.Fatal(err)
	}
	if err := c.CollectBPF(path, "not a filter ((("); err == nil {
		t.Fatal("invalid filter accepted")
	}
}
