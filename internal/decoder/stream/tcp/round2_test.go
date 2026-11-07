package tcp

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/gogo/protobuf/proto"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	"github.com/dreadl0ck/netcap/defaults"
	"github.com/dreadl0ck/netcap/internal/decoder"
	decoderconfig "github.com/dreadl0ck/netcap/internal/decoder/config"
	"github.com/dreadl0ck/netcap/internal/decoder/core"
	"github.com/dreadl0ck/netcap/internal/decoder/stream/imap"
	"github.com/dreadl0ck/netcap/internal/decoder/stream/ssh"
	"github.com/dreadl0ck/netcap/internal/netio"
	"github.com/dreadl0ck/netcap/internal/reassembly"
	"github.com/dreadl0ck/netcap/types"
)

type round2Writer struct {
	netio.AuditRecordWriter
	records []proto.Message
}

func (w *round2Writer) Write(m proto.Message) error {
	w.records = append(w.records, proto.Clone(m))
	return nil
}

// Synthetic packets use the CLI's admission defaults, not config.DefaultConfig's
// stricter library defaults. No SYN/data packet bypasses tcpConnection.Accept.
func round2Config(t *testing.T, d *decoder.StreamDecoder) *round2Writer {
	t.Helper()
	old := decoderconfig.Instance
	cfg := decoderconfig.DefaultConfig.Clone()
	cfg.AllowMissingInit, cfg.IgnoreFSMerr = defaults.AllowMissingInit, defaults.IgnoreFSMErr
	cfg.NoOptCheck, cfg.Checksum = defaults.NoOptCheck, defaults.Checksum
	cfg.StreamDecoderBufSize = 4096
	decoderconfig.Instance = cfg
	w := &round2Writer{}
	oldWriter, oldCount := d.Writer, d.NumRecordsWritten
	d.Writer = w
	t.Cleanup(func() {
		decoderconfig.Instance = old
		d.Writer, d.NumRecordsWritten = oldWriter, oldCount
	})
	return w
}

type round2Stream struct {
	*tcpConnection
	complete int
}

func (s *round2Stream) ReassemblyComplete(ac reassembly.AssemblerContext, flow gopacket.Flow, _ string) bool {
	s.complete++
	s.reorder(ac, flow)
	s.sortAndMergeFragments()
	s.decode()
	return true
}

type round2Factory struct{ streams []*round2Stream }

func (f *round2Factory) New(n, transport gopacket.Flow, ac reassembly.AssemblerContext) reassembly.Stream {
	c := &tcpConnection{
		net: n, transport: transport, firstPacket: ac.GetCaptureInfo().Timestamp,
		ident:      fmt.Sprintf("%s:%s->%s:%s", n.Src(), transport.Src(), n.Dst(), transport.Dst()),
		tcpstate:   reassembly.NewTCPSimpleFSM(reassembly.TCPSimpleFSMOptions{SupportMissingEstablishment: decoderconfig.Instance.AllowMissingInit}),
		optchecker: reassembly.NewTCPOptionCheck(),
	}
	c.client, c.server = c.newTCPStreamReader(true), c.newTCPStreamReader(false)
	s := &round2Stream{tcpConnection: c}
	f.streams = append(f.streams, s)
	return s
}

type round2Trace struct {
	assembler *reassembly.Assembler
	factory   *round2Factory
	port      layers.TCPPort
	stamp     int64
}

func newRound2Trace(port layers.TCPPort) *round2Trace {
	f := &round2Factory{}
	return &round2Trace{assembler: reassembly.NewAssembler(reassembly.NewStreamPool(f)), factory: f, port: port}
}

func (r *round2Trace) send(server bool, seq uint32, flags string, payload string) {
	r.stamp++
	n := gopacket.NewFlow(layers.EndpointIPv4, []byte{192, 0, 2, 1}, []byte{192, 0, 2, 2})
	p := &layers.TCP{SrcPort: 40000, DstPort: r.port, Seq: seq, Window: 65535,
		SYN: bytes.ContainsRune([]byte(flags), 'S'), ACK: bytes.ContainsRune([]byte(flags), 'A'),
		FIN: bytes.ContainsRune([]byte(flags), 'F'), RST: bytes.ContainsRune([]byte(flags), 'R')}
	if server {
		n = n.Reverse()
		p.SrcPort, p.DstPort, p.Ack = p.DstPort, p.SrcPort, 101
	} else if p.ACK {
		p.Ack = 201
	}
	p.Payload = []byte(payload)
	p.SetInternalPortsForTesting()
	r.assembler.AssembleWithContext(n, p, &context{CaptureInfo: gopacket.CaptureInfo{Timestamp: time.Unix(r.stamp, 123)}})
}

func TestRound2MissingSYNAndAsymmetricIMAP(t *testing.T) {
	for _, mode := range []string{"full", "no-client-syn", "client-only", "server-only", "no-handshake-client", "no-handshake-server"} {
		t.Run(mode, func(t *testing.T) {
			w := round2Config(t, imap.Decoder)
			r := newRound2Trace(143)
			client := mode != "server-only" && mode != "no-handshake-server"
			server := mode != "client-only" && mode != "no-handshake-client"
			if client && mode != "no-client-syn" && mode != "no-handshake-client" {
				r.send(false, 100, "S", "")
			}
			if server && mode != "no-handshake-server" {
				r.send(true, 200, "SA", "")
			}
			if server {
				r.send(true, 201, "A", "* OK ready\r\n")
			}
			if client {
				r.send(false, 101, "A", "A1 CAPABILITY\r\n")
			}
			r.assembler.FlushAll()
			want := 1
			if client && server {
				want = 2
			}
			if len(w.records) != want {
				t.Fatalf("got %d IMAP records, want %d", len(w.records), want)
			}
			for _, record := range w.records {
				m := record.(*types.IMAP)
				if client != server && !strings.Contains(m.Notes, "peer not observed") {
					t.Fatalf("one-sided record lacks qualification: %v", m)
				}
				if strings.HasPrefix(mode, "no-handshake") && !strings.Contains(m.Notes, "service port") {
					t.Fatalf("inferred role lacks qualification: %v", m)
				}
				if m.IsResponse && (m.SrcPort != 143 || m.Response != "OK") || !m.IsResponse && (m.SrcPort != 40000 || m.Command != "CAPABILITY") {
					t.Fatalf("role/message lost: %v", m)
				}
			}
		})
	}
}

func TestRound2AsymmetricSSH(t *testing.T) {
	for _, server := range []bool{false, true} {
		for _, syn := range []bool{false, true} {
			t.Run(fmt.Sprintf("server=%v/syn=%v", server, syn), func(t *testing.T) {
				w := round2Config(t, ssh.Decoder)
				r := newRound2Trace(22)
				if syn {
					flags := "S"
					if server {
						flags = "SA"
					}
					r.send(server, 100, flags, "")
				}
				r.send(server, 101, "A", "SSH-2.0-test_1.0\r\n")
				r.assembler.FlushAll()
				if len(w.records) != 1 {
					t.Fatalf("got %d SSH records", len(w.records))
				}
				m := w.records[0].(*types.SSH)
				if m.IsClient == server || m.Ident != "SSH-2.0-test_1.0" {
					t.Fatalf("role/ident: %v", m)
				}
			})
		}
	}
}

func TestRound2PostCloseObservedData(t *testing.T) {
	for _, flags := range []string{"R", "FA"} {
		t.Run(flags, func(t *testing.T) {
			w := round2Config(t, imap.Decoder)
			r := newRound2Trace(143)
			r.send(false, 100, "S", "")
			r.send(true, 200, "SA", "")
			r.send(false, 101, "A", "")
			r.send(false, 101, flags, "")
			r.send(false, 101, "A", "A1 CAPABILITY\r\n")
			r.assembler.FlushAll()
			if len(w.records) != 1 {
				t.Fatalf("lost observed command after %s: %d records", flags, len(w.records))
			}
			if !strings.Contains(w.records[0].(*types.IMAP).Notes, "endpoint delivery unconfirmed") {
				t.Fatal("exported IMAP record lost post-close qualification")
			}
			qualified := false
			for _, f := range r.factory.streams[0].client.DataSlice() {
				if len(f.Raw()) != 0 {
					qualified = f.(*core.StreamData).TCPObservation != ""
				}
			}
			if !qualified {
				t.Fatal("post-close bytes lost their delivery qualification")
			}
		})
	}
}

func TestRound2CloseBoundsAndIncarnations(t *testing.T) {
	for _, closeFlags := range []string{"R", "FA", ""} {
		t.Run(closeFlags, func(t *testing.T) {
			round2Config(t, imap.Decoder)
			r := newRound2Trace(143)
			r.send(false, 100, "S", "")
			r.send(true, 200, "SA", "")
			r.send(false, 101, "A", "A1 CAPABILITY\r\n")
			r.send(false, 116, closeFlags, "")
			r.send(false, 100, "S", "") // old opening retransmission
			if len(r.factory.streams) != 1 {
				t.Fatal("retransmission created an incarnation")
			}
			decoderconfig.Instance.Checksum = true
			r.send(false, 500, "S", "") // cannot validate without a network checksum
			decoderconfig.Instance.Checksum = defaults.Checksum
			if len(r.factory.streams) != 1 || r.factory.streams[0].complete != 0 {
				t.Fatal("invalid SYN retired a stream")
			}
			r.send(false, 500, "S", "")
			r.send(true, 900, "SA", "")
			r.send(false, 501, "A", "A2 CAPABILITY\r\n")
			r.assembler.FlushAll()
			if len(r.factory.streams) != 2 {
				t.Fatalf("incarnations=%d", len(r.factory.streams))
			}
			if got := string(r.factory.streams[0].client.DataSlice().Bytes()); got != "A1 CAPABILITY\r\n" {
				t.Fatalf("old bytes: %q", got)
			}
			if got := string(r.factory.streams[1].client.DataSlice().Bytes()); got != "A2 CAPABILITY\r\n" {
				t.Fatalf("new bytes: %q", got)
			}
		})
	}
}

func TestRound2PostCloseBudgetAndExpiry(t *testing.T) {
	round2Config(t, imap.Decoder)
	r := newRound2Trace(143)
	r.send(false, 100, "S", "")
	r.send(true, 200, "SA", "")
	r.send(false, 101, "A", "")
	r.send(false, 101, "R", "")
	r.send(false, 101, "A", strings.Repeat("x", maxPostCloseBytes+10))
	r.send(false, 101+maxPostCloseBytes+10, "A", strings.Repeat("x", 20))
	s := r.factory.streams[0]
	if s.client.DataSlice().Size() != maxPostCloseBytes {
		t.Fatalf("retained %d bytes", s.client.DataSlice().Size())
	}
	var discarded int64
	markers := 0
	for _, fragment := range s.client.DataSlice() {
		d := fragment.(*core.StreamData)
		if d.DiscardedBytes > 0 {
			discarded += d.DiscardedBytes
			markers++
			if d.DiscardReason != "tcp-post-close-budget" {
				t.Fatal(d.DiscardReason)
			}
		}
	}
	if discarded != 30 || markers != 1 {
		t.Fatalf("discarded=%d markers=%d", discarded, markers)
	}
	r.assembler.FlushWithOptions(reassembly.FlushOptions{TC: time.Unix(1000, 0)})
	if s.complete != 1 || r.assembler.FlushAll() != 0 {
		t.Fatal("post-close observer did not expire without live-idle maintenance")
	}
}

func TestRound2OneSidedStrictFSM(t *testing.T) {
	w := round2Config(t, imap.Decoder)
	decoderconfig.Instance.IgnoreFSMerr = false
	r := newRound2Trace(143)
	r.send(false, 100, "S", "")
	r.send(false, 101, "A", "A1 CAPABILITY\r\n")
	r.assembler.FlushAll()
	if len(w.records) != 1 {
		t.Fatal("missing establishment option did not admit a one-sided SYN/data trace")
	}
}

func TestRound2HalfCloseAndHole(t *testing.T) {
	for _, hole := range []bool{false, true} {
		t.Run(fmt.Sprint(hole), func(t *testing.T) {
			w := round2Config(t, imap.Decoder)
			r := newRound2Trace(143)
			r.send(false, 100, "S", "")
			r.send(true, 200, "SA", "")
			r.send(true, 201, "FA", "")
			r.send(false, 101, "A", "A1 CAPA")
			seq := uint32(108)
			if hole {
				seq++
			}
			r.send(false, seq, "A", "BILITY\r\n")
			r.assembler.FlushAll()
			if !hole && len(w.records) != 1 || hole && len(w.records) != 0 {
				t.Fatalf("hole=%v records=%d", hole, len(w.records))
			}
			for _, d := range r.factory.streams[0].client.DataSlice() {
				if d.(*core.StreamData).TCPObservation != "" {
					t.Fatal("peer FIN incorrectly qualified the still-open direction")
				}
			}
		})
	}
}

func TestRound2RejectedCloseDoesNotMutateFSM(t *testing.T) {
	round2Config(t, imap.Decoder)
	decoderconfig.Instance.NoOptCheck = false
	c := &tcpConnection{tcpstate: reassembly.NewTCPSimpleFSM(reassembly.TCPSimpleFSMOptions{SupportMissingEstablishment: true}), optchecker: reassembly.NewTCPOptionCheck()}
	c.Accept(&layers.TCP{ACK: true, Seq: 101}, reassembly.TCPDirClientToServer, -1)
	before := c.tcpstate.String()
	if c.Accept(&layers.TCP{RST: true, Seq: 90000}, reassembly.TCPDirClientToServer, 101) {
		t.Error("out-of-window reset accepted")
	}
	if got := c.tcpstate.String(); got != before {
		t.Errorf("rejected close changed FSM: %s -> %s", before, got)
	}
}

func TestRound2InvalidCloseValidation(t *testing.T) {
	for _, mode := range []string{"options", "checksum", "stale-fin", "future-fin", "rst-fin"} {
		t.Run(mode, func(t *testing.T) {
			round2Config(t, imap.Decoder)
			c := &tcpConnection{tcpstate: reassembly.NewTCPSimpleFSM(reassembly.TCPSimpleFSMOptions{SupportMissingEstablishment: true}), optchecker: reassembly.NewTCPOptionCheck()}
			c.Accept(&layers.TCP{ACK: true, Seq: 101}, reassembly.TCPDirClientToServer, -1)
			before := c.tcpstate.String()
			p := &layers.TCP{ACK: true, RST: true, Seq: 101}
			switch mode {
			case "options":
				p.Options = []layers.TCPOption{{OptionType: layers.TCPOptionKindTimestamps, OptionData: []byte{1}}}
			case "checksum":
				decoderconfig.Instance.Checksum = true
			case "stale-fin":
				p.RST, p.FIN, p.Seq = false, true, 100
			case "future-fin":
				p.RST, p.FIN, p.Seq = false, true, 90000
			case "rst-fin":
				p.FIN = true
			}
			if c.Accept(p, reassembly.TCPDirClientToServer, 101) || c.tcpstate.String() != before || c.resetObserved {
				t.Fatal("invalid close accepted or changed state")
			}
		})
	}
}

func TestRound2SSHRoleDoesNotFollowTimestampOrPortOrder(t *testing.T) {
	w := round2Config(t, ssh.Decoder)
	r := newRound2Trace(64999)
	r.send(false, 100, "S", "")
	r.stamp = -2
	r.send(true, 200, "SA", "") // earlier timestamp does not reverse SYN roles
	r.stamp = 2
	r.send(false, 101, "A", "SSH-2.0-client_1.0\r\n")
	r.send(true, 201, "A", "SSH-2.0-server_1.0\r\n")
	r.assembler.FlushAll()
	if len(w.records) != 2 {
		t.Fatalf("records=%d", len(w.records))
	}
	for _, p := range w.records {
		m := p.(*types.SSH)
		if m.IsClient != strings.Contains(m.Ident, "client") || m.Timestamp != time.Unix(map[bool]int64{true: 3, false: 4}[m.IsClient], 123).UnixNano() {
			t.Fatal("SSH roles or directional timestamps swapped")
		}
	}
}

func TestRound2SYNRefusalAcknowledgesOpening(t *testing.T) {
	for _, ack := range []uint32{0, 100, 101, 90000} {
		t.Run(fmt.Sprint(ack), func(t *testing.T) {
			round2Config(t, imap.Decoder)
			r := newRound2Trace(143)
			r.send(false, 100, "S", "")
			c := r.factory.streams[0].tcpConnection
			accepted := c.Accept(&layers.TCP{RST: true, ACK: true, Seq: 0, Ack: ack}, reassembly.TCPDirServerToClient, -1)
			if accepted != (ack == 101) || c.resetObserved != accepted {
				t.Fatalf("ack=%d accepted=%v reset=%v", ack, accepted, c.resetObserved)
			}
			r.assembler.FlushAll()
		})
	}
}
