package tcp

import (
	"bytes"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/gogo/protobuf/proto"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	decoderconfig "github.com/dreadl0ck/netcap/decoder/config"
	"github.com/dreadl0ck/netcap/decoder/stream/modbus"
	streamutils "github.com/dreadl0ck/netcap/decoder/stream/utils"
	netio "github.com/dreadl0ck/netcap/io"
	"github.com/dreadl0ck/netcap/reassembly"
	"github.com/dreadl0ck/netcap/types"
)

// Use real assembler delivery and TCP readers without starting background workers.
type captureSpanStream struct{ *tcpConnection }

func (s *captureSpanStream) Accept(*layers.TCP, reassembly.TCPFlowDirection, reassembly.Sequence) bool {
	return true
}

func (s *captureSpanStream) ReassemblyComplete(reassembly.AssemblerContext, gopacket.Flow, string) bool {
	return true
}

func (s *captureSpanStream) New(net, transport gopacket.Flow, _ reassembly.AssemblerContext) reassembly.Stream {
	s.net, s.transport = net, transport
	return s
}

type modbusCaptureWriter struct {
	netio.AuditRecordWriter
	records []*types.Modbus
}

func (w *modbusCaptureWriter) Write(msg proto.Message) error {
	w.records = append(w.records, proto.Clone(msg).(*types.Modbus))
	return nil
}

func TestTCPModbusCaptureSpans(t *testing.T) {
	previous := decoderconfig.Instance
	writer, count := modbus.Decoder.Writer, modbus.Decoder.NumRecordsWritten
	t.Cleanup(func() {
		decoderconfig.Instance = previous
		modbus.Decoder.Writer, modbus.Decoder.NumRecordsWritten = writer, count
	})
	cfg := *decoderconfig.DefaultConfig
	cfg.StreamDecoderBufSize = 32
	cfg.IncludePayloads = true
	decoderconfig.Instance = &cfg
	a := []byte{0, 1, 0, 0, 0, 6, 1, 3, 0, 1, 0, 2}
	b := []byte{0, 2, 0, 0, 0, 6, 1, 3, 0, 3, 0, 4}
	for _, server := range []bool{false, true} {
		for _, split := range []int{len(a), 9} {
			t.Run(fmt.Sprintf("server=%t/split=%d", server, split), func(t *testing.T) {
				conn := &tcpConnection{ident: "capture-spans"}
				conn.client, conn.server = conn.newTCPStreamReader(true), conn.newTCPStreamReader(false)
				assembler := reassembly.NewAssembler(reassembly.NewStreamPool(&captureSpanStream{conn}))
				net := gopacket.NewFlow(layers.EndpointIPv4, []byte{192, 0, 2, 1}, []byte{192, 0, 2, 2})
				send := func(reverse bool, seq uint32, syn bool, data []byte, stamp int64) *context {
					t.Helper()
					flow := net
					packet := &layers.TCP{SrcPort: 12345, DstPort: 502, Seq: seq, SYN: syn, ACK: reverse || !syn}
					if reverse {
						flow = net.Reverse()
						packet.SrcPort, packet.DstPort = packet.DstPort, packet.SrcPort
					}
					packet.Payload = bytes.Clone(data)
					packet.SetInternalPortsForTesting()
					ac := &context{CaptureInfo: gopacket.CaptureInfo{Timestamp: time.Unix(stamp, 123), CaptureLength: len(data) + 40, Length: len(data) + 40, InterfaceIndex: int(stamp)}}
					assembler.AssembleWithContext(flow, packet, ac)
					// Delivery must not retain the live packet's backing array.
					clear(packet.Payload)
					return ac
				}
				send(false, 100, true, nil, 1)
				if server {
					send(true, 100, true, nil, 2)
				}
				all := append(bytes.Clone(a), b...)
				second := send(server, 101+uint32(split), false, all[split:], 10)
				first := send(server, 101, false, all[:split], 20)
				assembler.FlushAll()
				fragments := conn.client.DataSlice()
				if server {
					fragments = conn.server.DataSlice()
				}
				if len(fragments) != 2 || !bytes.Equal(fragments.Bytes(), all) {
					t.Fatalf("capture boundaries/order: %d fragments, %x", len(fragments), fragments.Bytes())
				}
				for i, want := range []*context{first, second} {
					if fragments[i].Context() != want || !reflect.DeepEqual(fragments[i].CaptureInfo(), want.GetCaptureInfo()) {
						t.Fatalf("fragment %d lost capture metadata", i)
					}
				}
				w := &modbusCaptureWriter{}
				modbus.Decoder.Writer = w
				conn.sortAndMergeFragments()
				// The conversation buffer is a byte stream: the delivery above
				// carries the later-captured packet that closed the hole first,
				// so ordering the merge by timestamp would swap the two spans.
				if !bytes.Equal(conn.merged.Bytes(), all) || len(conn.merged) != 2 {
					t.Fatalf("merged byte order: %d fragments, %x", len(conn.merged), conn.merged.Bytes())
				}
				conn.decode()
				if len(w.records) != 2 {
					t.Fatalf("got %d Modbus records", len(w.records))
				}
				src, dst, srcPort, dstPort := "192.0.2.1", "192.0.2.2", int32(12345), int32(502)
				if server {
					src, dst, srcPort, dstPort = dst, src, dstPort, srcPort
				}
				for i, r := range w.records {
					wantTime := first.GetCaptureInfo().Timestamp
					if i == 1 {
						wantTime = second.GetCaptureInfo().Timestamp
					}
					if r.TransactionID != int32(i+1) || r.Timestamp != wantTime.UnixNano() || r.SrcIP != src || r.DstIP != dst || r.SrcPort != srcPort || r.DstPort != dstPort || !bytes.Equal(r.Payload, all[i*len(a)+7:(i+1)*len(a)]) {
						t.Fatalf("record %d order/timestamp/endpoints/payload: %v", i, r)
					}
				}
			})
		}
	}
}

// A queued segment larger than one reassembly page is delivered as several
// containers that all carry the packet's capture information, so their
// timestamps are identical. The merge must keep them in stream order without
// relying on how equal timestamps are broken, and the extra containers must not
// be counted as extra packets.
func TestTCPMultiPageSegmentKeepsByteOrder(t *testing.T) {
	previous := decoderconfig.Instance
	t.Cleanup(func() { decoderconfig.Instance = previous })
	cfg := *decoderconfig.DefaultConfig
	cfg.StreamDecoderBufSize = 32
	decoderconfig.Instance = &cfg

	conn := &tcpConnection{ident: "multi-page"}
	conn.client, conn.server = conn.newTCPStreamReader(true), conn.newTCPStreamReader(false)
	assembler := reassembly.NewAssembler(reassembly.NewStreamPool(&captureSpanStream{conn}))
	flow := gopacket.NewFlow(layers.EndpointIPv4, []byte{192, 0, 2, 1}, []byte{192, 0, 2, 2})
	send := func(seq uint32, syn bool, data []byte, stamp int64) {
		t.Helper()
		packet := &layers.TCP{SrcPort: 12345, DstPort: 502, Seq: seq, SYN: syn, ACK: !syn}
		packet.Payload = bytes.Clone(data)
		packet.SetInternalPortsForTesting()
		assembler.AssembleWithContext(flow, packet, &context{CaptureInfo: gopacket.CaptureInfo{Timestamp: time.Unix(stamp, 0), CaptureLength: len(data), Length: len(data)}})
		// Pages must copy out of the live packet's backing array.
		clear(packet.Payload)
	}

	// Distinct in every position, so any swapped span is visible.
	all := make([]byte, 4096)
	for i := range all {
		all[i] = byte(i%251) + 1
	}
	const head = 8

	streamutils.Stats.Lock()
	packetsBefore := streamutils.Stats.Pkt
	streamutils.Stats.Unlock()

	send(100, true, nil, 1)
	send(101+head, false, all[head:], 10) // queued out of order, split into pages
	send(101, false, all[:head], 20)      // closes the hole and releases the pages
	assembler.FlushAll()

	fragments := conn.client.DataSlice()
	if len(fragments) != 4 {
		t.Fatalf("want the head packet plus 3 pages, got %d fragments", len(fragments))
	}
	for i, f := range fragments[2:] {
		if !f.CaptureInfo().Timestamp.Equal(fragments[1].CaptureInfo().Timestamp) {
			t.Fatalf("continuation page %d does not share the packet timestamp", i)
		}
	}

	conn.sortAndMergeFragments()
	if !bytes.Equal(conn.merged.Bytes(), all) {
		t.Fatal("merged lost the byte order of a multi-page segment")
	}

	streamutils.Stats.Lock()
	packets := streamutils.Stats.Pkt - packetsBefore
	streamutils.Stats.Unlock()
	if packets != 3 {
		t.Fatalf("counted %d packets, want 3: continuation pages are not packets", packets)
	}
}
