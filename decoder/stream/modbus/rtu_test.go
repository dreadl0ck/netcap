package modbus

import (
	"bytes"
	"testing"
	"time"

	decoderconfig "github.com/dreadl0ck/netcap/decoder/config"
	"github.com/dreadl0ck/netcap/decoder/core"
	"github.com/dreadl0ck/netcap/types"
)

func rtuWire(unit byte, pdu ...byte) []byte {
	b := append([]byte{unit}, pdu...)
	c := crc16RTU(b)
	return append(b, byte(c), byte(c>>8))
}

func TestRTUCRC(t *testing.T) {
	if got := crc16RTU([]byte("123456789")); got != 0x4b37 {
		t.Fatalf("CRC: %04x", got)
	}
	if got := rtuWire(1, 3, 0, 0, 0, 10); !bytes.Equal(got, []byte{1, 3, 0, 0, 0, 10, 0xc5, 0xcd}) {
		t.Fatalf("wire: %x", got)
	}
}

func TestRTULayoutsAndSplits(t *testing.T) {
	for _, tt := range []struct{ pdu, role string }{
		{"0100000001", "request"}, {"010101", "response"}, {"0200000001", "request"}, {"020100", "response"},
		{"0300000001", "request"}, {"03020001", "response"}, {"0400000001", "request"}, {"04020001", "response"},
		{"050010ff00", "request"}, {"050010ff00", "response"}, {"0600101234", "request"}, {"0600101234", "response"},
		{"0800020000", "request"}, {"0800021234", "response"},
		{"0f00100009028101", "request"}, {"0f00100009", "response"},
		{"1000100002041234ffff", "request"}, {"1000100002", "response"},
		{"140706000100020002", "request"}, {"140605061234ffff", "response"},
		{"150b060001000200021234ffff", "request"}, {"150b060001000200021234ffff", "response"},
		{"160010ff0000ff", "request"}, {"160010ff0000ff", "response"},
		{"170010000200200001021234", "request"}, {"17040001ffff", "response"},
		{"2b0e0400", "request"}, {"2b0e0181ff0302000141010142", "response"}, {"8302", "response"},
		{"07", "request"}, {"07ff", "response"},
		{"0b", "request"}, {"0bffff0009", "response"},
		{"0c", "request"}, {"0c07ffff0009000420", "response"},
		{"11", "request"}, {"1103fe0102", "response"},
		{"180010", "request"}, {"18000600021234ffff", "response"},
	} {
		t.Run(tt.pdu+tt.role, func(t *testing.T) {
			m := reader(t)
			m.conversation.TCPHandshakeComplete = true
			decoderconfig.Instance.ModbusRTUEndpoints = "192.0.2.2:502"
			pdu := pduBytes(t, tt.pdu)
			b := rtuWire(247, pdu...)
			all := append(bytes.Clone(b), b...)
			for split := 0; split <= len(all); split++ {
				m.conversation.Data = core.DataFragments{fragment(all[:split], 100, tt.role == "response"), fragment(all[split:], 200, tt.role == "response")}
				got := records(m)
				if len(got) != 2 {
					t.Fatalf("split %d: %v", split, got)
				}
				for _, r := range got {
					if r.Transport != "rtu_tcp" || r.HasMBAP || !r.HasChecksum || !r.ChecksumValid || r.TransactionID != 0 || r.UnitID != 247 || r.MessageRole != tt.role || !bytes.Equal(r.Payload, pdu) {
						t.Fatalf("record: %v", r)
					}
				}
			}
		})
	}
}

func TestRTURecovery(t *testing.T) {
	m := reader(t)
	m.conversation.TCPHandshakeComplete = true
	decoderconfig.Instance.ModbusRTUEndpoints = "192.0.2.2:502"
	a := rtuWire(1, 3, 0, 0, 0, 10)
	bad := bytes.Clone(a)
	bad[len(bad)-1] ^= 1
	for _, prefix := range [][]byte{bad, bytes.Repeat([]byte{255}, 10000), {1, 3, 250}, rtuWire(248, 3, 0, 0, 0, 10), rtuWire(1, 43, 13, 1, 1), rtuWire(1, 8, 0, 0, 1, 2, 3, 4)} {
		m.conversation.Data = core.DataFragments{fragment(append(bytes.Clone(prefix), a...), 1, false)}
		got := records(m)
		// However many bytes the scan discards, one contiguous loss event is
		// reported once, ahead of the frame it recovered.
		if len(got) != 2 || !isLoss(got[0], 0, "rtu_tcp") || got[1].CorrelationStatus != "ambiguous" {
			t.Fatalf("prefix %x: %v", prefix[:min(12, len(prefix))], got)
		}
	}
	first, second := fragment(a[:4], 1, false), fragment(a[4:], 2, false)
	second.SkippedBytes = 3
	m.conversation.Data = core.DataFragments{first, second, fragment(a, 3, false)}
	got := records(m)
	if len(got) != 2 || !isLoss(got[0], 3, "rtu_tcp") || got[0].Timestamp != 2 || got[1].Timestamp != 3 {
		t.Fatalf("crossed gap: %v", got)
	}
}

func TestRTUGapLossAndResume(t *testing.T) {
	m := reader(t)
	m.conversation.TCPHandshakeComplete = true
	decoderconfig.Instance.ModbusRTUEndpoints = "192.0.2.2:502"
	request, response := rtuWire(1, 3, 0, 0, 0, 2), rtuWire(1, 3, 4, 0, 1, 0, 2)
	gap := fragment(nil, 20, false)
	gap.SkippedBytes = 9
	m.conversation.ClientData = core.DataFragments{fragment(request[:4], 10, false), gap, fragment(request, 30, false)}
	m.conversation.ServerData = core.DataFragments{fragment(response, 40, true)}
	got := records(m)
	if len(got) != 3 || countLoss(got) != 1 {
		t.Fatalf("got %v", got)
	}
	if !isLoss(got[0], 9, "rtu_tcp") || got[0].Timestamp != 20 || got[0].SrcIP != "192.0.2.1" {
		t.Fatalf("gap marker: %v", got[0])
	}
	// The truncated frame is dropped, the frame after the gap decodes, and the
	// opposite direction is unaffected.
	if got[1].MessageRole != "request" || got[1].Timestamp != 30 || got[2].MessageRole != "response" {
		t.Fatalf("resumed frames: %v", got)
	}
	// RTU pairs requests and responses positionally rather than by transaction
	// ID, so a loss leaves every later pairing ambiguous.
	if got[2].CorrelationStatus != "ambiguous" {
		t.Fatalf("correlation across loss: %v", got)
	}
}

// Back to back gaps are one loss event reporting the extent of the whole run.
func TestRTUSummedLossExtent(t *testing.T) {
	m := reader(t)
	m.conversation.TCPHandshakeComplete = true
	decoderconfig.Instance.ModbusRTUEndpoints = "192.0.2.2:502"
	a := rtuWire(1, 3, 0, 0, 0, 10)
	first, second := fragment(nil, 10, false), fragment(nil, 20, false)
	first.SkippedBytes, second.SkippedBytes = 5, 7
	m.conversation.ClientData = core.DataFragments{first, second, fragment(a, 30, false)}
	got := records(m)
	if len(got) != 2 || !isLoss(got[0], 12, "rtu_tcp") || got[0].Timestamp != 10 || got[1].Timestamp != 30 {
		t.Fatalf("summed extent: %v", got)
	}
	// A contributing gap of unknown extent makes the whole event unknown.
	decoderconfig.Instance.AllowMissingInit = true
	unknown := fragment(nil, 15, false)
	unknown.SkippedBytes = -1
	m.conversation.ClientData = core.DataFragments{first, unknown, second, fragment(a, 30, false)}
	got = records(m)
	if len(got) != 2 || !isLoss(got[0], -1, "rtu_tcp") || got[0].Timestamp != 10 {
		t.Fatalf("unknown extent: %v", got)
	}
}

func TestRTUBroadcastAndCorrelation(t *testing.T) {
	m := reader(t)
	m.conversation.TCPHandshakeComplete = true
	decoderconfig.Instance.ModbusRTUEndpoints = "192.0.2.2:502"
	b := rtuWire(0, 6, 0, 1, 0, 2)
	a := rtuWire(1, 3, 0, 1, 0, 1)
	r := rtuWire(1, 3, 2, 0, 2)
	m.conversation.Data = core.DataFragments{fragment(b, 1, false), fragment(a, 2, false), fragment(r, 3, true)}
	got := records(m)
	if len(got) != 3 || !got[0].Broadcast || got[0].MessageRole != "request" || got[0].CorrelationStatus != "not_applicable" || got[2].CorrelationStatus != "matched" || got[2].RequestTimestamp != 2 || got[2].ResponseLatency != 1 {
		t.Fatalf("correlation: %v", got)
	}
	// Neither direction frames unit zero here, so both report unusable bytes.
	m.conversation.Data = core.DataFragments{fragment(rtuWire(0, 3, 0, 1, 0, 1), 1, false), fragment(b, 2, true)}
	got = records(m)
	if len(got) != 2 || !isLoss(got[0], 0, "rtu_tcp") || !isLoss(got[1], 0, "rtu_tcp") ||
		got[0].SrcIP != "192.0.2.1" || got[1].SrcIP != "192.0.2.2" {
		t.Fatalf("invalid unit zero: %v", got)
	}
	m.conversation.Data = core.DataFragments{fragment(a, 1, false), fragment(a, 2, false), fragment(r, 3, true)}
	got = records(m)
	if len(got) != 3 || got[2].CorrelationStatus != "ambiguous" {
		t.Fatalf("overlap: %v", got)
	}
	decoderconfig.Instance.AllowMissingInit = true
	m.conversation.Data = core.DataFragments{fragment(rtuWire(1, 6, 0, 1, 0, 2), 1, false)}
	m.conversation.Data[0].(*core.StreamData).SkippedBytes = -1
	got = records(m)
	if len(got) != 1 || got[0].MessageRole != "unknown" || got[0].CorrelationStatus != "ambiguous" {
		t.Fatalf("midstream echo: %v", got)
	}
	decoderconfig.Instance.AllowMissingInit = false
	// A rejected initial-loss marker now says why the direction stays silent.
	if got := records(m); len(got) != 1 || !isLoss(got[0], -1, "rtu_tcp") || got[0].Timestamp != 1 {
		t.Fatalf("missing init disabled: %v", got)
	}
}

func TestRTUBroadcastDiagnostics(t *testing.T) {
	m := reader(t)
	m.conversation.TCPHandshakeComplete = true
	decoderconfig.Instance.ModbusRTUEndpoints = "192.0.2.2:502"
	// Restart communications, force listen only and clear counters are the
	// disruptive diagnostics a master may broadcast.
	for _, sub := range []byte{1, 4, 10} {
		m.conversation.Data = core.DataFragments{fragment(rtuWire(0, 8, 0, sub, 0, 0), 1, false)}
		got := records(m)
		if len(got) != 1 || !got[0].Broadcast || got[0].UnitID != 0 || got[0].MessageRole != "request" || got[0].ParseStatus != "valid" ||
			got[0].FunctionCode != 8 || !got[0].HasDiagnostic || got[0].DiagnosticSubfunction != uint32(sub) || got[0].CorrelationStatus != "not_applicable" {
			t.Fatalf("subfunction %d: %v", sub, got)
		}
	}
	// Return Query Data has no determined length and is not a broadcast, so the
	// bytes are reported as unframed rather than guessed at.
	m.conversation.Data = core.DataFragments{fragment(rtuWire(0, 8, 0, 0, 0, 0), 1, false)}
	if got := records(m); len(got) != 1 || !isLoss(got[0], 0, "rtu_tcp") {
		t.Fatalf("broadcast query data: %v", got)
	}
}

func TestRTUAdversarialScanCost(t *testing.T) {
	previous := decoderconfig.Instance
	decoderconfig.Instance = &decoderconfig.Config{}
	t.Cleanup(func() { decoderconfig.Instance = previous })
	// Every third offset is a plausible frame start claiming a determined
	// length, so rescanning the whole window per byte verifies a checksum per
	// offset. These runs took tens of seconds before the scan cursor.
	for _, tt := range []struct {
		role string
		size int
	}{{"request", 1 << 19}, {"unknown", 1 << 15}} {
		t.Run(tt.role, func(t *testing.T) {
			data := bytes.Repeat([]byte{1, 3, 100}, tt.size/3)
			var d rtuDirection
			start := time.Now()
			d.feed(data, 1, tt.role, true, func(msg *types.Modbus) { t.Fatalf("emitted: %+v", msg) }, func() {})
			if elapsed := time.Since(start); elapsed > 5*time.Second {
				t.Fatalf("%d bytes took %v", len(data), elapsed)
			}
		})
	}
}

func TestRTUNoHandshakeAndEmbeddedCRC(t *testing.T) {
	m := reader(t)
	decoderconfig.Instance.ModbusRTUEndpoints = "192.0.2.2:502"
	request := rtuWire(1, 3, 0, 1, 0, 1)
	response := rtuWire(1, 3, 2, 0, 2)
	m.conversation.Data = core.DataFragments{fragment(request, 1, false), fragment(response, 2, true)}
	got := records(m)
	if len(got) != 2 || got[0].MessageRole != "request" || got[1].MessageRole != "response" || got[1].CorrelationStatus != "ambiguous" {
		t.Fatalf("inferred roles must not match without handshake: %v", got)
	}
	// A CRC-valid ADU in register values is payload, not a nested frame.
	m.conversation.TCPHandshakeComplete = true
	pdu := append([]byte{16, 0, 0, 0, 4, 8}, request...)
	outer := rtuWire(1, pdu...)
	for split := 0; split <= len(outer); split++ {
		m.conversation.Data = core.DataFragments{fragment(outer[:split], 1, false), fragment(outer[split:], 2, false)}
		got = records(m)
		if len(got) != 1 || got[0].FunctionCode != 16 {
			t.Fatalf("nested CRC split %d: %v", split, got)
		}
	}
	decoderconfig.Instance.ModbusRTUEndpoints = "192.0.2.1:12345"
	if IsRTUConversation(m.conversation) {
		t.Fatal("initialized source is not a configured destination")
	}
	m.conversation.TCPHandshakeComplete = false
	if !IsRTUConversation(m.conversation) {
		t.Fatal("midstream reverse endpoint not selected")
	}
}

func FuzzRTUFraming(f *testing.F) {
	previous := decoderconfig.Instance
	decoderconfig.Instance = &decoderconfig.Config{}
	f.Cleanup(func() { decoderconfig.Instance = previous })
	f.Add(rtuWire(1, 3, 0, 0, 0, 10), byte(3))
	f.Add([]byte{1, 43, 14, 1, 1, 0, 0, 255}, byte(1))
	f.Fuzz(func(t *testing.T, b []byte, split byte) {
		if len(b) > 4096 {
			return
		}
		var d rtuDirection
		emit := func(m *types.Modbus) {
			if m.HasMBAP || !m.ChecksumValid || m.ParseStatus != "valid" || m.UnitID > 247 {
				t.Fatalf("invalid emission: %v", m)
			}
		}
		n := min(int(split), len(b))
		d.feed(b[:n], 1, "unknown", false, emit, func() {})
		d.feed(b[n:], 2, "unknown", true, emit, func() {})
	})
}
