package collector

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
)

func inputPCAPHeader(order binary.ByteOrder, nano bool, snap uint32, link layers.LinkType) []byte {
	h := make([]byte, 24)
	magic := uint32(0xa1b2c3d4)
	if nano {
		magic = 0xa1b23c4d
	}
	order.PutUint32(h, magic)
	order.PutUint16(h[4:], 2)
	order.PutUint16(h[6:], 4)
	order.PutUint32(h[16:], snap)
	order.PutUint32(h[20:], uint32(link))
	return h
}

func inputPCAPRecord(order binary.ByteOrder, stamp, fraction, captured, wire uint32, data []byte) []byte {
	h := make([]byte, 16)
	order.PutUint32(h, stamp)
	order.PutUint32(h[4:], fraction)
	order.PutUint32(h[8:], captured)
	order.PutUint32(h[12:], wire)
	return append(h, data...)
}

func inputNGBlock(order binary.ByteOrder, kind uint32, body []byte) []byte {
	b := make([]byte, len(body)+12)
	order.PutUint32(b, kind)
	order.PutUint32(b[4:], uint32(len(b)))
	copy(b[8:], body)
	order.PutUint32(b[len(b)-4:], uint32(len(b)))
	return b
}

func inputNGSection(order binary.ByteOrder) []byte {
	b := make([]byte, 16)
	order.PutUint32(b, 0x1a2b3c4d)
	order.PutUint16(b[4:], 1)
	order.PutUint64(b[8:], ^uint64(0))
	return inputNGBlock(order, ngSection, b)
}

func inputNGInterface(order binary.ByteOrder, lt layers.LinkType, snap uint32, options ...byte) []byte {
	b := make([]byte, 8)
	order.PutUint16(b, uint16(lt))
	order.PutUint32(b[4:], snap)
	return inputNGBlock(order, 1, append(b, options...))
}

func inputNGPacket(order binary.ByteOrder, iface, captured, wire uint32, data []byte) []byte {
	b := make([]byte, 20+((len(data)+3)&^3))
	order.PutUint32(b, iface)
	order.PutUint32(b[8:], 1234567)
	order.PutUint32(b[12:], captured)
	order.PutUint32(b[16:], wire)
	copy(b[20:], data)
	return inputNGBlock(order, 6, b)
}

func scanInputBytes(t *testing.T, data []byte, ng, process bool) (CaptureInputReport, [][]byte, []gopacket.CaptureInfo) {
	t.Helper()
	var r captureReader
	var err error
	if ng {
		r, err = newBoundedNGReader(bytes.NewReader(data))
	} else {
		r, err = newBoundedPCAPReader(bytes.NewReader(data))
	}
	if err != nil {
		t.Fatal(err)
	}
	var packets [][]byte
	var infos []gopacket.CaptureInfo
	report := CaptureInputReport{}
	var visit func([]byte, gopacket.CaptureInfo) bool
	if process {
		visit = func(data []byte, ci gopacket.CaptureInfo) bool {
			packets = append(packets, data)
			infos = append(infos, ci)
			return true
		}
	}
	walkCaptureInput(context.Background(), r, &report, visit)
	report.result()
	return report, packets, infos
}

func TestCaptureReaderPCAPRecovery(t *testing.T) {
	for _, order := range []binary.ByteOrder{binary.LittleEndian, binary.BigEndian} {
		for _, nanos := range []bool{false, true} {
			good := rawPacketFixture(t, false, 64)
			prefix := inputPCAPHeader(order, nanos, 1, layers.LinkTypeEthernet)
			prefix = append(prefix, inputPCAPRecord(order, 10, 456789, 64, 64, good)...)
			suffix := inputPCAPRecord(order, 12, 1, 64, 64, good)
			for _, tc := range []struct {
				name           string
				tail           []byte
				count, skipped int64
				eof            bool
			}{
				{"clean", suffix, 2, 0, true},
				{"caplen-origlen", append(inputPCAPRecord(order, 11, 0, 64, 63, good), suffix...), 2, 1, true},
				{"timestamp", append(inputPCAPRecord(order, 11, 1_000_000_000, 64, 64, good), suffix...), 2, 1, true},
				{"short-header", suffix[:9], 1, 0, false},
				{"short-payload", suffix[:20], 1, 0, false},
				{"missing-payload", suffix[:16], 1, 0, false},
				{"hard-cap", append(inputPCAPRecord(order, 11, 0, maxInputPacket+1, maxInputPacket+1, nil), suffix...), 1, 0, false},
			} {
				t.Run(order.String()+"/"+tc.name+map[bool]string{true: "/nano", false: "/micro"}[nanos], func(t *testing.T) {
					input := append(bytes.Clone(prefix), tc.tail...)
					count, _, _ := scanInputBytes(t, input, false, false)
					got, packets, infos := scanInputBytes(t, input, false, true)
					if !reflect.DeepEqual(count, got) || got.ProcessedPackets != tc.count || got.SkippedRecords != tc.skipped || got.ReachedEOF != tc.eof {
						t.Fatalf("count/process: %+v / %+v", count, got)
					}
					if got.SnaplenOverrides != tc.count || !bytes.Equal(packets[0], good) || infos[0].Timestamp.Unix() != 10 {
						t.Fatal("lost bytes or timestamps while overriding snaplen")
					}
					wantFrac := 456789
					if !nanos {
						wantFrac *= 1000
					}
					if infos[0].Timestamp.Nanosecond() != wantFrac {
						t.Fatal("timestamp precision lost")
					}
					if tc.name != "clean" && got.result() == nil {
						t.Fatal("corruption reported as success")
					}
				})
			}
			var compressed bytes.Buffer
			gz := gzip.NewWriter(&compressed)
			_, _ = gz.Write(prefix)
			if err := gz.Close(); err != nil {
				t.Fatal(err)
			}
			got, packets, _ := scanInputBytes(t, compressed.Bytes(), false, true)
			if got.ProcessedPackets != 1 || got.result() != nil || !bytes.Equal(packets[0], good) {
				t.Fatal("gzip changed packet")
			}
		}
	}
}

func TestCaptureReaderNGBoundaries(t *testing.T) {
	for _, order := range []binary.ByteOrder{binary.LittleEndian, binary.BigEndian} {
		good := rawPacketFixture(t, false, 64)
		prefix := append(inputNGSection(order), inputNGInterface(order, 1, 1)...)
		packet := inputNGPacket(order, 0, 64, 64, good)
		prefix = append(prefix, packet...)
		badTrailer := bytes.Clone(packet)
		order.PutUint32(badTrailer[len(badTrailer)-4:], 12)
		badLength := bytes.Clone(packet[:8])
		order.PutUint32(badLength[4:], 7)
		for _, tc := range []struct {
			name           string
			bad            []byte
			count, skipped int64
			eof            bool
		}{
			{"caplen-origlen", inputNGPacket(order, 0, 64, 63, good), 2, 1, true},
			{"caplen-block", inputNGPacket(order, 0, 100, 100, good), 2, 1, true},
			{"packet-cap", inputNGPacket(order, 0, maxInputPacket+1, maxInputPacket+1, nil), 2, 1, true},
			{"absent-interface", inputNGPacket(order, 1, 64, 64, good), 2, 1, true},
			{"short-packet-header", inputNGBlock(order, 6, nil), 2, 1, true},
			{"trailer", badTrailer, 1, 0, false},
			{"length", badLength, 1, 0, false},
			{"short-body", packet[:17], 1, 0, false},
		} {
			t.Run(order.String()+"/"+tc.name, func(t *testing.T) {
				input := append(append(bytes.Clone(prefix), tc.bad...), packet...)
				count, _, _ := scanInputBytes(t, input, true, false)
				got, packets, _ := scanInputBytes(t, input, true, true)
				if !reflect.DeepEqual(count, got) || got.ProcessedPackets != tc.count || got.SkippedRecords != tc.skipped || got.ReachedEOF != tc.eof || got.result() == nil {
					t.Fatalf("count/process: %+v / %+v", count, got)
				}
				for _, p := range packets {
					if !bytes.Equal(p, good) {
						t.Fatal("payload changed or aliased")
					}
				}
			})
		}
	}
}

func TestCaptureReaderNGInterfacesAndTime(t *testing.T) {
	le, be := binary.LittleEndian, binary.BigEndian
	data := rawPacketFixture(t, false, 64)
	input := append(inputNGSection(le), inputNGInterface(le, 1, 0)...)
	// Invalid if_tsresol still consumes interface ID 1.
	input = append(input, inputNGInterface(le, 276, 0, 9, 0, 0, 0)...)
	input = append(input, inputNGInterface(le, 104, 0)...)
	input = append(input, inputNGPacket(le, 1, 64, 64, data)...)
	input = append(input, inputNGPacket(le, 2, 64, 64, data)...)
	input = append(input, inputNGSection(be)...)
	// Seconds resolution (explicit exponent zero), signed offset -1.
	options := []byte{0, 9, 0, 1, 0, 0, 0, 0, 0, 14, 0, 8, 255, 255, 255, 255, 255, 255, 255, 255}
	input = append(input, inputNGInterface(be, 239, 0, options...)...)
	input = append(input, inputNGPacket(be, 0, 64, 64, data)...)
	report, _, infos := scanInputBytes(t, input, true, true)
	if report.ProcessedPackets != 2 || report.SkippedRecords != 2 || !report.ReachedEOF {
		t.Fatalf("%+v", report)
	}
	if infos[0].InterfaceIndex != 2 || infos[1].InterfaceIndex != 3 || infos[1].AncillaryData[0] != layers.LinkType(239) || infos[1].Timestamp.Unix() != 1234566 {
		t.Fatalf("section scope/time: %+v", infos)
	}
	if !infos[0].Timestamp.Equal(time.Unix(1, 234567000)) {
		t.Fatal("microsecond conversion")
	}
}

func TestCaptureReaderNGSimpleAndObsoletePacket(t *testing.T) {
	order := binary.LittleEndian
	packet := rawPacketFixture(t, false, 64)
	input := append(inputNGSection(order), inputNGInterface(order, 1, 64)...)
	body := make([]byte, 4)
	order.PutUint32(body, 100)
	input = append(input, inputNGBlock(order, 3, append(body, packet...))...)
	old := inputNGPacket(order, 0, 64, 64, packet)
	order.PutUint32(old, 2)
	order.PutUint16(old[10:], 12) // PB drops count, not part of interface id.
	input = append(input, old...)
	report, packets, infos := scanInputBytes(t, input, true, true)
	if report.ProcessedPackets != 2 || report.Unsupported != 1 || report.result() == nil || !infos[0].Timestamp.IsZero() || infos[0].Length != 100 || !bytes.Equal(packets[1], packet) {
		t.Fatalf("SPB/PB: %+v %+v", report, infos)
	}
}

func TestCaptureReaderInteropAndBounds(t *testing.T) {
	var b bytes.Buffer
	w, err := pcapgo.NewNgWriter(&b, layers.LinkTypeEthernet)
	if err != nil {
		t.Fatal(err)
	}
	data := rawPacketFixture(t, false, 64)
	ci := gopacket.CaptureInfo{Timestamp: time.Unix(123, 456789012), CaptureLength: len(data), Length: len(data)}
	if err := w.WritePacket(ci, data); err != nil {
		t.Fatal(err)
	}
	if err := w.Flush(); err != nil {
		t.Fatal(err)
	}
	report, packets, infos := scanInputBytes(t, b.Bytes(), true, true)
	if report.result() != nil || !bytes.Equal(packets[0], data) || !infos[0].Timestamp.Equal(ci.Timestamp) {
		t.Fatalf("pcapgo interop: %+v %+v", report, infos)
	}
	r, err := newBoundedPCAPReader(bytes.NewReader(append(inputPCAPHeader(binary.LittleEndian, false, ^uint32(0), 1), inputPCAPRecord(binary.LittleEndian, 1, 0, 64, 64, data)...)))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := r.ZeroCopyReadPacketData(); err != nil || cap(r.buffer) > maxInputPacket {
		t.Fatalf("snaplen allocation: %v %d", err, cap(r.buffer))
	}
	bad := append(inputPCAPHeader(binary.LittleEndian, false, 64, 1), inputPCAPRecord(binary.LittleEndian, 1, 0, ^uint32(0), ^uint32(0), nil)...)
	r, err = newBoundedPCAPReader(bytes.NewReader(bad))
	if err != nil {
		t.Fatal(err)
	}
	_, _, first := r.ReadPacketData()
	_, _, second := r.ReadPacketData()
	if first == nil || !errors.Is(second, first) {
		t.Fatal("terminal failure was not sticky")
	}
}

func TestCaptureReaderResourceLimits(t *testing.T) {
	order := binary.LittleEndian
	for _, size := range []uint32{maxInputBlock + 4, ^uint32(0) &^ 3} {
		input := append(inputNGSection(order), make([]byte, 8)...)
		order.PutUint32(input[len(input)-8:], 6)
		order.PutUint32(input[len(input)-4:], size)
		r, err := newBoundedNGReader(bytes.NewReader(input))
		if err != nil {
			t.Fatal(err)
		}
		_, _, err = r.ReadPacketData()
		var readErr *captureReadError
		if !errors.As(err, &readErr) || readErr.Recoverable || cap(r.buffer) > maxInputBlock {
			t.Fatalf("block cap bypass: %v, allocation %d", err, cap(r.buffer))
		}
	}
	input := inputNGSection(order)
	for range maxInputInterfaces {
		// Invalid descriptors must count against the budget too.
		input = append(input, inputNGBlock(order, 1, nil)...)
	}
	input = append(input, inputNGSection(order)...)
	input = append(input, inputNGInterface(order, 1, 0)...)
	r, err := newBoundedNGReader(bytes.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	for range maxInputInterfaces {
		_, _, err := r.ReadPacketData()
		var readErr *captureReadError
		if !errors.As(err, &readErr) || !readErr.Recoverable {
			t.Fatalf("malformed IDB did not retain its identity: %v", err)
		}
	}
	_, _, err = r.ReadPacketData()
	var readErr *captureReadError
	if !errors.As(err, &readErr) || readErr.Recoverable || r.interfaceBase != maxInputInterfaces || len(r.interfaces) != 0 {
		t.Fatalf("cross-section interface cap bypass: %v", err)
	}
}

func TestCaptureReaderEpochAndGzipTruncation(t *testing.T) {
	order := binary.LittleEndian
	packet := rawPacketFixture(t, false, 64)
	input := append(inputPCAPHeader(order, false, 64, 1), inputPCAPRecord(order, 0, 0, 64, 64, packet)...)
	report, _, infos := scanInputBytes(t, input, false, true)
	if report.result() != nil || !infos[0].Timestamp.Equal(time.Unix(0, 0)) {
		t.Fatalf("epoch zero substituted: %+v %+v", report, infos)
	}
	var compressed bytes.Buffer
	gz := gzip.NewWriter(&compressed)
	if _, err := gz.Write(input); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	data := compressed.Bytes()
	report, packets, _ := scanInputBytes(t, data[:len(data)-4], false, true)
	if report.result() == nil || report.ProcessedPackets != 1 || report.ReachedEOF || !bytes.Equal(packets[0], packet) {
		t.Fatalf("truncated gzip lost prefix or claimed complete: %+v", report)
	}
}

func TestCaptureReaderCountCancellation(t *testing.T) {
	for _, ng := range []bool{false, true} {
		input := inputPCAPHeader(binary.LittleEndian, false, 64, 1)
		if ng {
			input = inputNGSection(binary.LittleEndian)
		}
		path := filepath.Join(t.TempDir(), "empty.capture")
		if err := os.WriteFile(path, input, 0600); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		count, err := countCaptureInput(ctx, path, ng)
		if count != 0 || !errors.Is(err, context.Canceled) {
			t.Fatalf("ng=%t: canceled counting returned %d, %v", ng, count, err)
		}
	}
}

func FuzzCaptureReaders(f *testing.F) {
	f.Add(inputPCAPHeader(binary.LittleEndian, false, 64, 1), false)
	f.Add(inputNGSection(binary.LittleEndian), true)
	f.Fuzz(func(t *testing.T, data []byte, ng bool) {
		if len(data) > 65536 {
			t.Skip()
		}
		var r captureReader
		var err error
		if ng {
			r, err = newBoundedNGReader(bytes.NewReader(data))
		} else {
			r, err = newBoundedPCAPReader(bytes.NewReader(data))
		}
		if err != nil {
			return
		}
		for i := 0; i <= len(data)/12+1; i++ {
			payload, ci, err := r.ZeroCopyReadPacketData()
			if err == io.EOF {
				return
			}
			if err != nil {
				var re *captureReadError
				if !errors.As(err, &re) || !re.Recoverable {
					return
				}
				continue
			}
			if len(payload) > maxInputPacket || ci.CaptureLength != len(payload) || ci.Length < len(payload) {
				t.Fatal("reader violated length bound")
			}
		}
		t.Fatal("reader made no progress")
	})
}
