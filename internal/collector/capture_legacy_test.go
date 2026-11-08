package collector

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gopacket/gopacket/layers"
)

func TestLegacyPCAPLengthsAndRouting(t *testing.T) {
	for _, order := range []binary.ByteOrder{binary.LittleEndian, binary.BigEndian} {
		for minor := uint16(0); minor <= 4; minor++ {
			for _, oldOrder := range []bool{false, true} {
				if minor < 3 && !oldOrder || minor == 4 && oldOrder {
					continue
				}
				for _, nano := range []bool{false, true} {
					for _, compressed := range []bool{false, true} {
						t.Run(fmt.Sprintf("%s/2.%d/old=%t/nano=%t/gzip=%t", order, minor, oldOrder, nano, compressed), func(t *testing.T) {
							data := inputPCAPHeader(order, nano, 1, layers.LinkTypeEthernet)
							order.PutUint16(data[6:], minor)
							// Unequal lengths expose the historical field swap; the second
							// record proves that the first did not consume its header.
							first, second := uint32(3), uint32(9)
							if oldOrder {
								first, second = second, first
							}
							data = append(data, inputPCAPRecord(order, 123, 456789, first, second, []byte{1, 2, 3})...)
							data = append(data, inputPCAPRecord(order, 124, 0, 2, 2, []byte{4, 5})...)
							if compressed {
								var b bytes.Buffer
								w := gzip.NewWriter(&b)
								if _, err := w.Write(data); err != nil {
									t.Fatal(err)
								}
								if err := w.Close(); err != nil {
									t.Fatal(err)
								}
								data = b.Bytes()
							}
							path := filepath.Join(t.TempDir(), "capture.bin")
							if err := os.WriteFile(path, data, 0600); err != nil {
								t.Fatal(err)
							}
							if classic, err := IsPcap(path); err != nil || !classic {
								t.Fatalf("routing classic=%t: %v", classic, err)
							}
							if count, err := countCaptureInput(context.Background(), path, false); err != nil || count != 2 {
								t.Fatalf("count=%d: %v", count, err)
							}
							for _, reuse := range []bool{false, true} {
								r, err := NewCaptureReader(bytes.NewReader(data))
								if err != nil {
									t.Fatal(err)
								}
								read := r.ReadPacketData
								if reuse {
									read = r.ZeroCopyReadPacketData
								}
								packet, ci, err := read()
								ns := int64(456789000)
								if nano {
									ns = 456789
								}
								if err != nil || !bytes.Equal(packet, []byte{1, 2, 3}) || ci.CaptureLength != 3 || ci.Length != 9 || !ci.Timestamp.Equal(time.Unix(123, ns)) || !inputPacketInfo(ci).SnaplenOverride {
									t.Fatalf("first packet=%x info=%+v err=%v", packet, ci, err)
								}
								packet, ci, err = read()
								if err != nil || !bytes.Equal(packet, []byte{4, 5}) || ci.Length != 2 {
									t.Fatalf("second packet=%x info=%+v err=%v", packet, ci, err)
								}
								if _, _, err := read(); err != io.EOF {
									t.Fatalf("end=%v", err)
								}
							}
						})
					}
				}
			}
		}
	}
}

func TestLegacyPCAPBoundedFailures(t *testing.T) {
	le := binary.LittleEndian
	for _, minor := range []uint16{0, 1, 2, 3} {
		for _, tc := range []struct {
			name    string
			caplen  uint32
			payload []byte
			reason  string
		}{
			{"oversize", maxInputPacket + 1, nil, "hard packet cap"},
			{"truncated", 4, []byte{1}, "truncated PCAP payload"},
		} {
			t.Run(fmt.Sprintf("2.%d/%s", minor, tc.name), func(t *testing.T) {
				data := inputPCAPHeader(le, false, 65535, 1)
				le.PutUint16(data[6:], minor)
				data = append(data, inputPCAPRecord(le, 1, 0, tc.caplen+1, tc.caplen, tc.payload)...)
				r, err := NewPCAPReader(bytes.NewReader(data))
				if err != nil {
					t.Fatal(err)
				}
				if _, _, err = r.ReadPacketData(); err == nil || !strings.Contains(err.Error(), tc.reason) {
					t.Fatalf("got %v, want %s", err, tc.reason)
				}
				if _, _, next := r.ReadPacketData(); next != err {
					t.Fatalf("terminal error changed: %v -> %v", err, next)
				}
			})
		}
	}
	for _, version := range [][2]uint16{{1, 0}, {2, 5}, {3, 0}} {
		data := inputPCAPHeader(le, false, 65535, 1)
		le.PutUint16(data[4:], version[0])
		le.PutUint16(data[6:], version[1])
		path := filepath.Join(t.TempDir(), "unsupported.pcap")
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		if classic, err := IsPcap(path); err != nil || !classic {
			t.Fatalf("unsupported PCAP misrouted: %t %v", classic, err)
		}
		if _, err := NewCaptureReader(bytes.NewReader(data)); err == nil || !strings.Contains(err.Error(), "unsupported PCAP version") {
			t.Fatalf("version %v: %v", version, err)
		}
	}
	path := filepath.Join(t.TempDir(), "truncated.pcap")
	if err := os.WriteFile(path, []byte{0xd4, 0xc3, 0xb2, 0xa1}, 0600); err != nil {
		t.Fatal(err)
	}
	if classic, err := IsPcap(path); err != nil || !classic {
		t.Fatalf("truncated PCAP misrouted: %t %v", classic, err)
	}
}
