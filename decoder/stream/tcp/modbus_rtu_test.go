package tcp

import (
	"bytes"
	"net"
	"testing"
	"time"

	decoderconfig "github.com/dreadl0ck/netcap/decoder/config"
	"github.com/dreadl0ck/netcap/decoder/stream/modbus"
	"github.com/dreadl0ck/netcap/decoder/stream/tls"
	"github.com/dreadl0ck/netcap/reassembly"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

type rtuTCPStream struct{ captureSpanStream }

func (s *rtuTCPStream) Accept(p *layers.TCP, d reassembly.TCPFlowDirection, seq reassembly.Sequence) bool {
	return s.tcpConnection.Accept(p, d, seq)
}

func (s *rtuTCPStream) New(n, transport gopacket.Flow, _ reassembly.AssemblerContext) reassembly.Stream {
	s.net, s.transport = n, transport
	return s
}

func TestTCPConfiguredRTURouting(t *testing.T) {
	previous := decoderconfig.Instance
	writer, count := modbus.Decoder.Writer, modbus.Decoder.NumRecordsWritten
	t.Cleanup(func() {
		decoderconfig.Instance = previous
		modbus.Decoder.Writer, modbus.Decoder.NumRecordsWritten = writer, count
	})
	for _, endpoint := range []string{"", "192.0.2.3:502", "192.0.2.2:1502", "192.0.2.2:502", "[2001:db8::2]:502"} {
		t.Run(endpoint, func(t *testing.T) {
			cfg := *decoderconfig.DefaultConfig
			cfg.StreamDecoderBufSize, cfg.ModbusRTUEndpoints = 32, endpoint
			cfg.NoOptCheck, cfg.Checksum = true, false
			decoderconfig.Instance = &cfg
			conn := &tcpConnection{ident: "rtu-routing", tcpstate: reassembly.NewTCPSimpleFSM(reassembly.TCPSimpleFSMOptions{}), optchecker: reassembly.NewTCPOptionCheck()}
			conn.client, conn.server = conn.newTCPStreamReader(true), conn.newTCPStreamReader(false)
			assembler := reassembly.NewAssembler(reassembly.NewStreamPool(&rtuTCPStream{captureSpanStream{conn}}))
			flow := gopacket.NewFlow(layers.EndpointIPv4, []byte{192, 0, 2, 1}, []byte{192, 0, 2, 2})
			if endpoint == "[2001:db8::2]:502" {
				flow = gopacket.NewFlow(layers.EndpointIPv6, net.ParseIP("2001:db8::1").To16(), net.ParseIP("2001:db8::2").To16())
			}
			send := func(reverse bool, seq uint32, syn bool, data []byte, stamp int64) {
				p := &layers.TCP{SrcPort: 12345, DstPort: 502, Seq: seq, SYN: syn, ACK: reverse || !syn}
				if reverse {
					p.Ack = 101
				} else if !syn {
					p.Ack = 201
				}
				n := flow
				if reverse {
					n = flow.Reverse()
					p.SrcPort, p.DstPort = p.DstPort, p.SrcPort
				}
				p.Payload = bytes.Clone(data)
				p.SetInternalPortsForTesting()
				assembler.AssembleWithContext(n, p, &context{CaptureInfo: gopacket.CaptureInfo{Timestamp: time.Unix(stamp, 0)}})
			}
			send(false, 100, true, nil, 1)
			send(true, 200, true, nil, 2)
			a := []byte{1, 3, 0, 0, 0, 10, 0xc5, 0xcd}
			send(false, 101, false, a[:3], 3)
			send(false, 104, false, append(bytes.Clone(a[3:]), a...), 4)
			assembler.FlushAll()
			if conn.initStage != 3 {
				t.Fatalf("handshake stage %d", conn.initStage)
			}
			w := &modbusCaptureWriter{}
			modbus.Decoder.Writer = w
			conn.sortAndMergeFragments()
			conn.decode()
			want := 0
			if endpoint == "192.0.2.2:502" || endpoint == "[2001:db8::2]:502" {
				want = 2
			}
			if len(w.records) != want {
				t.Fatalf("got %d records, want %d", len(w.records), want)
			}
			for _, r := range w.records {
				if r.Transport != "rtu_tcp" || r.HasMBAP || !r.ChecksumValid || r.MessageRole != "request" {
					t.Fatalf("not RTU: %v", r)
				}
			}
		})
	}
}

// Excluding the Modbus decoder leaves its writer nil. A configured RTU endpoint
// must then not claim the connection, or excluding Modbus would silently switch
// off stream decoding for every connection to that endpoint.
func TestTCPConfiguredRTUFallsBackWhenModbusExcluded(t *testing.T) {
	previous := decoderconfig.Instance
	modbusWriter := modbus.Decoder.Writer
	certWriter, recordWriter, count := tls.Decoder.Writer, tls.RecordDecoder.Writer, tls.RecordDecoder.NumRecordsWritten
	t.Cleanup(func() {
		decoderconfig.Instance = previous
		modbus.Decoder.Writer = modbusWriter
		tls.Decoder.Writer, tls.RecordDecoder.Writer, tls.RecordDecoder.NumRecordsWritten = certWriter, recordWriter, count
	})

	cfg := *decoderconfig.DefaultConfig
	cfg.StreamDecoderBufSize, cfg.ModbusRTUEndpoints = 32, "192.0.2.2:502"
	decoderconfig.Instance = &cfg
	modbus.Decoder.Writer = nil

	w := &tlsCaptureWriter{}
	tls.Decoder.Writer, tls.RecordDecoder.Writer = nil, w

	// TLS application data on the configured RTU port.
	conn := newMergeTestConn([]string{string([]byte{23, 3, 3, 0, 2, 1, 2})}, nil, time.Unix(1, 0))
	conn.net = gopacket.NewFlow(layers.EndpointIPv4, []byte{192, 0, 2, 1}, []byte{192, 0, 2, 2})
	conn.transport = gopacket.NewFlow(layers.EndpointTCPPort, []byte{0x30, 0x39}, []byte{0x01, 0xf6})

	conn.sortAndMergeFragments()
	conn.decode()

	if len(w.records) != 1 || w.records[0].ContentType != 23 || w.records[0].DstPort != 502 {
		t.Fatalf("no fallback decoder ran for the RTU endpoint: %v", w.records)
	}
}
