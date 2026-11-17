package collector

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/dreadl0ck/netcap/internal/evidence"
	"github.com/dreadl0ck/netcap/internal/packetview"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
)

func TestSourceOrdinalsSurviveRejectedRecordsAndRetention(t *testing.T) {
	frame := rawPacketFixture(t, false, 64)
	for _, ng := range []bool{false, true} {
		for _, order := range []binary.ByteOrder{binary.LittleEndian, binary.BigEndian} {
			t.Run(captureByteOrder(order)+map[bool]string{false: "-pcap", true: "-pcapng"}[ng], func(t *testing.T) {
				var input []byte
				if ng {
					input = append(inputNGSection(order), inputNGInterface(order, layers.LinkTypeEthernet, 65535)...)
					input = append(input, inputNGPacket(order, 0, 64, 64, frame)...)
					input = append(input, inputNGPacket(order, 99, 64, 64, frame)...)
					input = append(input, inputNGPacket(order, 0, 64, 64, frame)...)
				} else {
					input = inputPCAPHeader(order, false, 65535, layers.LinkTypeEthernet)
					input = append(input, inputPCAPRecord(order, 1, 17, 64, 64, frame)...)
					input = append(input, inputPCAPRecord(order, 2, 18, 64, 32, frame)...)
					input = append(input, inputPCAPRecord(order, 3, 19, 64, 64, frame)...)
				}
				report, _, infos := scanInputBytes(t, input, ng, true)
				if len(infos) != 2 || report.SourcePacketRecords != 3 || report.Issues[0].Ordinal != 2 {
					t.Fatal("source record count was renumbered", report)
				}
				c := rawPacketCollector(1, 2, gopacket.Default)
				for _, ci := range infos {
					c.handleRawPacketData(bytes.Clone(frame), &ci)
				}
				var ordinals []uint64
				for range 2 {
					packet := <-c.workers[0]
					c.wg.Done()
					view := packetview.FromCapture(packet.Metadata().CaptureInfo)
					if view == nil || len(view.Packets) != 1 {
						t.Fatal("missing original capture reference")
					}
					ordinals = append(ordinals, view.Packets[0].Ordinal)
					releaseRawPacket(packet)
				}
				if !reflect.DeepEqual(ordinals, []uint64{1, 3}) {
					t.Fatal("admission renumbered source records", ordinals)
				}
				path := filepath.Join(t.TempDir(), "input.pcap")
				if err := os.WriteFile(path, input, 0600); err != nil {
					t.Fatal(err)
				}
				out := t.TempDir()
				configuration := ultimateCaptureConfig(out, 1, 0)
				configuration.CaptureEvidence, configuration.RetainPackets = true, true
				configuration.DecoderConfig.IncludeDecoders = "UDP"
				collector := New(configuration)
				collect := collector.CollectPcap
				if ng {
					collect = collector.CollectPcapNG
				}
				if err := collect(path); err == nil {
					t.Fatal("rejected record became complete input")
				}
				manifest := bookJSON[evidence.CaptureManifest](t, filepath.Join(out, "capture-manifest.json"))
				if manifest.SourcePacketRecords != 3 || manifest.IngressPackets != 2 || manifest.OrdinalNamespaces["packetReferences"] != "input-packet-one-based" || manifest.OrdinalNamespaces["retainedSegmentBounds"] != "capture-ingress-zero-based" {
					t.Fatal("ordinal namespaces or denominators lost", manifest)
				}
				if len(manifest.Segments) != 1 || manifest.Segments[0].FirstOrdinal != 0 || manifest.Segments[0].LastOrdinal != 1 {
					t.Fatal("retained ingress indexes changed", manifest.Segments)
				}
				file, err := os.Open(filepath.Join(out, manifest.Segments[0].Name))
				if err != nil {
					t.Fatal(err)
				}
				defer file.Close()
				reader, err := pcapgo.NewNgReader(file, pcapgo.DefaultNgReaderOptions)
				if err != nil {
					t.Fatal(err)
				}
				for index, want := range []uint64{1, 3} {
					data, _, options, err := reader.ReadPacketDataWithOptions()
					if err != nil || options.PacketID == nil || *options.PacketID != want || !bytes.Equal(data, frame) || len(options.Comments) != 1 {
						t.Fatal("retention lost packet identity", want, options, err)
					}
					var source evidence.SourcePacket
					if err := json.Unmarshal([]byte(options.Comments[0]), &source); err != nil {
						t.Fatal(err)
					}
					wantSource := inputPacketInfo(infos[index]).Source
					digest := sha256.Sum256(frame)
					wantSource.SHA256 = hex.EncodeToString(digest[:])
					if !reflect.DeepEqual(source, wantSource) {
						t.Fatal("retention changed byte/timestamp provenance", source, wantSource)
					}
				}
			})
		}
	}
}

func TestSourceOrdinalsExcludeMetadataErrorsAndSpanSections(t *testing.T) {
	order := binary.LittleEndian
	frame := rawPacketFixture(t, false, 64)
	input := append(inputNGSection(order), inputNGInterface(order, layers.LinkTypeEthernet, 65535)...)
	input = append(input, inputNGPacket(order, 0, 64, 64, frame)...)
	input = append(input, inputNGBlock(order, 1, make([]byte, 4))...)
	input = append(input, inputNGPacket(order, 0, 64, 64, frame)...)
	input = append(input, inputNGSection(order)...)
	input = append(input, inputNGInterface(order, layers.LinkTypeEthernet, 65535)...)
	input = append(input, inputNGPacket(order, 0, 64, 64, frame)...)
	report, _, infos := scanInputBytes(t, input, true, true)
	if report.SourcePacketRecords != 3 || len(infos) != 3 || report.Issues[0].Ordinal != 0 {
		t.Fatal("metadata error consumed a packet ordinal", report)
	}
	for index, ci := range infos {
		if inputPacketInfo(ci).Source.Ordinal != uint64(index+1) {
			t.Fatal("packet ordinal changed across section")
		}
	}
	last := inputPacketInfo(infos[2]).Source
	if last.Section != 1 || last.Interface != 0 || infos[2].InterfaceIndex != 2 || last.TimestampTicks != 1234567 || last.TimestampUnits != 1000000 {
		t.Fatal("section or original timestamp lost", last, infos[2])
	}
}

func TestSourceTimestampRetainsUnnormalizedWireValues(t *testing.T) {
	input := append(inputPCAPHeader(binary.BigEndian, true, 65535, layers.LinkTypeEthernet), inputPCAPRecord(binary.BigEndian, 1, 2000000000, 0, 0, nil)...)
	r, err := newBoundedPCAPReader(bytes.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	_, ci, err := r.ReadPacketData()
	if err != nil {
		t.Fatal(err)
	}
	info := inputPacketInfo(ci)
	if !info.TimestampNormalized || ci.Timestamp.Unix() != 3 || info.Source.TimestampSeconds != 1 || info.Source.TimestampFraction != 2000000000 || info.Source.TimestampUnits != 1000000000 {
		t.Fatal("wire timestamp was overwritten by normalization", info, ci)
	}
	report := CaptureInputReport{}
	for index := range 32 {
		report.issue(0, "read", "control", true, uint64(index+1))
	}
	if len(report.Issues) != 16 || report.Issues[15].Ordinal != 16 {
		t.Fatal("bounded issue provenance was overwritten", report.Issues)
	}
}
