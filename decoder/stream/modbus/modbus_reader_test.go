package modbus

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/gogo/protobuf/proto"
	"github.com/gopacket/gopacket"
	"github.com/prometheus/client_golang/prometheus"

	decoderconfig "github.com/dreadl0ck/netcap/decoder/config"
	"github.com/dreadl0ck/netcap/decoder/core"
	netio "github.com/dreadl0ck/netcap/io"
	"github.com/dreadl0ck/netcap/reassembly"
	"github.com/dreadl0ck/netcap/types"
)

func wire(id byte, pdu ...byte) []byte {
	length := len(pdu) + 1
	return append([]byte{0, id, 0, 0, byte(length >> 8), byte(length), 1}, pdu...)
}

func fragment(data []byte, timestamp int64, server bool) *core.StreamData {
	d := &core.StreamData{RawData: data, CaptureInformation: gopacket.CaptureInfo{Timestamp: time.Unix(0, timestamp)}}
	if server {
		d.Dir = reassembly.TCPDirServerToClient
	}
	return d
}

func reader(t *testing.T) *modbusReader {
	t.Helper()
	config := decoderconfig.Instance
	t.Cleanup(func() { decoderconfig.Instance = config })
	decoderconfig.Instance = &decoderconfig.Config{IncludePayloads: true}
	return &modbusReader{conversation: &core.ConversationInfo{
		ClientIP: "192.0.2.1", ServerIP: "192.0.2.2", ClientPort: 12345, ServerPort: 502,
		CommunityID: "community", FirstClientPacket: time.Unix(99, 0),
	}}
}

func records(m *modbusReader) (result []*types.Modbus) {
	m.frameConversation(func(r *types.Modbus) { result = append(result, r) })
	return
}

// isLoss checks the full shape of a capture-loss marker: no decoded message,
// but transport, endpoints and the reported gap size.
func isLoss(r *types.Modbus, lost int64, transport string) bool {
	return r.ParseStatus == "lost" && r.LostBytes == lost && r.Transport == transport &&
		r.MessageRole == "unknown" && r.CorrelationStatus == "not_applicable" &&
		r.ParseError != "" && r.CommunityID == "community" &&
		!r.HasMBAP && r.FunctionCode == 0 && r.Payload == nil
}

func countLoss(records []*types.Modbus) (n int) {
	for _, r := range records {
		if r.ParseStatus == "lost" {
			n++
		}
	}
	return
}

func TestFramingBoundaries(t *testing.T) {
	m := reader(t)
	a, b, c := wire(1, 3, 0, 1, 0, 2), wire(2, 0x83, 2), wire(3, 7)
	all := append(append(append([]byte{}, a...), b...), c...)
	starts := []int{0, len(a), len(a) + len(b)}
	payloads := [][]byte{a[7:], b[7:], c[7:]}
	for split := 0; split <= len(all); split++ {
		m.conversation.ClientData = core.DataFragments{fragment(all[:split], 100, false), fragment(all[split:], 200, false)}
		got := records(m)
		if len(got) != 3 {
			t.Fatalf("split %d: got %v", split, got)
		}
		for i, r := range got {
			wantTime := int64(100)
			if starts[i] >= split {
				wantTime = 200
			}
			if r.TransactionID != int32(i+1) || r.Timestamp != wantTime || r.SrcIP != "192.0.2.1" || r.DstIP != "192.0.2.2" || r.SrcPort != 12345 || r.DstPort != 502 || r.CommunityID != "community" {
				t.Fatalf("split %d record %d: %v", split, i, r)
			}
			if !bytes.Equal(r.Payload, payloads[i]) {
				t.Fatalf("split %d record %d payload: %x", split, i, r.Payload)
			}
		}
		if !got[1].Exception || got[1].FunctionCode != 3 || !bytes.Equal(got[1].Payload, b[7:]) || got[1].Length != 3 || got[1].UnitID != 1 || got[1].ProtocolID != 0 {
			t.Fatalf("exception/payload semantics: %v", got[1])
		}
	}
	m.conversation.ClientData = nil
	for i := range all {
		m.conversation.ClientData = append(m.conversation.ClientData, fragment(all[i:i+1], int64(i+1), false))
	}
	got := records(m)
	if len(got) != 3 {
		t.Fatalf("bytewise: %v", got)
	}
	for i, r := range got {
		if r.Timestamp != int64(starts[i]+1) {
			t.Fatalf("bytewise timestamp: %v", r)
		}
	}
}

type captureContext struct{ gopacket.CaptureInfo }

func (c captureContext) GetCaptureInfo() gopacket.CaptureInfo { return c.CaptureInfo }

func TestDirectionsAndSequence(t *testing.T) {
	for _, fallback := range []bool{false, true} {
		t.Run(fmt.Sprint(fallback), func(t *testing.T) {
			m := reader(t)
			a, b := wire(1, 3, 0, 1, 0, 2), wire(2, 3, 2, 0, 1)
			c1, c2 := fragment(a[:4], 300, false), fragment(a[4:], 100, false)
			s1, s2 := fragment(b[:8], 200, true), fragment(b[8:], 400, true)
			c1.AssemblerContext = captureContext{gopacket.CaptureInfo{Timestamp: time.Unix(0, 250)}}
			s1.AssemblerContext = captureContext{gopacket.CaptureInfo{Timestamp: time.Unix(0, 200)}}
			m.conversation.Data = core.DataFragments{c1, s1, c2, s2}
			if !fallback {
				m.conversation.ClientData = core.DataFragments{c1, c2}
				m.conversation.ServerData = core.DataFragments{s1, s2}
				// The timestamp-sorted combined view must not override TCP order.
				m.conversation.Data = core.DataFragments{c2, s1, c1, s2}
			}
			got := records(m)
			if len(got) != 2 || got[0].TransactionID != 1 || got[0].Timestamp != 250 || got[1].TransactionID != 2 || got[1].Timestamp != 200 {
				t.Fatalf("sequence/time: %v", got)
			}
			r := got[1]
			if r.SrcIP != "192.0.2.2" || r.DstIP != "192.0.2.1" || r.SrcPort != 502 || r.DstPort != 12345 || r.CommunityID != "community" || !bytes.Equal(r.Payload, b[7:]) {
				t.Fatalf("response endpoints/payload: %v", r)
			}
		})
	}
}

type wrappedFragment struct{ *core.StreamData }

func TestWrappedFragmentStopsDirection(t *testing.T) {
	for _, fallback := range []bool{false, true} {
		for _, server := range []bool{false, true} {
			for _, cut := range []int{0, 4, 8} {
				for _, empty := range []bool{false, true} {
					t.Run(fmt.Sprintf("fallback=%t/server=%t/cut=%d/empty=%t", fallback, server, cut, empty), func(t *testing.T) {
						m := reader(t)
						a := wire(1, 3, 0, 1, 0, 2)
						wrapped := &wrappedFragment{fragment([]byte{0xff}, 3, server)}
						if empty {
							wrapped.RawData = nil
							wrapped.SkippedBytes = -1
						}
						// Skipping the wrapper would stitch the two pieces into a false ADU.
						affected := core.DataFragments{
							fragment(wire(2, 7), 1, server), fragment(a[:cut], 2, server),
							wrapped, fragment(a[cut:], 4, server), fragment(wire(3, 7), 5, server),
						}
						other := fragment(wire(4, 7), 6, !server)
						if fallback {
							m.conversation.Data = append(affected, other)
						} else if server {
							m.conversation.ServerData = affected
							m.conversation.ClientData = core.DataFragments{other}
						} else {
							m.conversation.ClientData = affected
							m.conversation.ServerData = core.DataFragments{other}
						}
						got := records(m)
						if len(got) != 3 || got[0].TransactionID != 2 || got[2].TransactionID != 4 {
							t.Fatalf("must retain prior ADU and opposite direction only: %v", got)
						}
						// A fragment of unknown type has neither a gap size nor a
						// known frame start, so the direction cannot resume.
						if !isLoss(got[1], -1, "tcp") || got[1].Timestamp != 3 {
							t.Fatalf("loss marker: %v", got[1])
						}
						if (got[1].SrcIP == "192.0.2.2") != server {
							t.Fatalf("loss marker direction: %v", got[1])
						}
					})
				}
			}
		}
	}
}

// TestGapsAndTruncation pins the resume rule: after a gap the framer makes
// exactly one attempt at the first byte that follows it, and never slides
// forward through a body hunting for a plausible MBAP header.
func TestGapsAndTruncation(t *testing.T) {
	a := wire(1, 3, 0, 1, 0, 2)
	for _, server := range []bool{false, true} {
		for cut := 0; cut <= len(a); cut++ {
			for _, gap := range []int{12, -1} {
				t.Run(fmt.Sprintf("server=%t/cut=%d/gap=%d", server, cut, gap), func(t *testing.T) {
					m := reader(t)
					loss := fragment(nil, 2, server)
					loss.SkippedBytes = gap
					m.conversation.Data = core.DataFragments{
						fragment(a[:cut], 1, server), loss,
						fragment(a[cut:], 3, server), fragment(a, 4, server),
						fragment(wire(2, 7), 5, !server),
					}
					got := records(m)
					// Zero marks the expected loss record, any other value the
					// timestamp of a decoded ADU. Resumption happens only where
					// the data after the gap starts on an ADU boundary; a
					// truncated ADU is never emitted.
					want := []int64{0}
					switch {
					case gap > 0 && cut == 0:
						want = []int64{0, 3, 4}
					case gap > 0 && cut == len(a):
						want = []int64{1, 0, 4}
					case cut == len(a):
						want = []int64{1, 0}
					}
					if len(got) != len(want)+1 || countLoss(got) != 1 {
						t.Fatalf("got %v", got)
					}
					if got[len(got)-1].TransactionID != 2 {
						t.Fatalf("opposite direction: %v", got)
					}
					for i, timestamp := range want {
						r := got[i]
						if timestamp != 0 {
							if r.ParseStatus == "lost" || r.TransactionID != 1 || r.Timestamp != timestamp {
								t.Fatalf("record %d: %v", i, r)
							}
							continue
						}
						if !isLoss(r, int64(gap), "tcp") || r.Timestamp != 2 {
							t.Fatalf("loss marker %d: %v", i, r)
						}
						if (r.SrcIP == "192.0.2.2") != server {
							t.Fatalf("loss marker direction: %v", r)
						}
					}
				})
			}
		}
	}
	// Initial loss suppresses an otherwise complete ADU in the same fragment,
	// but the direction now says so.
	m := reader(t)
	d := fragment(a, 1, false)
	d.SkippedBytes = -1
	m.conversation.ClientData = core.DataFragments{d}
	got := records(m)
	if len(got) != 1 || !isLoss(got[0], -1, "tcp") || got[0].Timestamp != 1 {
		t.Fatalf("initial loss: %v", got)
	}
	// A direction ending on an ADU boundary stays silent; one ending inside an
	// ADU reports that parsing stopped.
	for _, tail := range []int{0, 4} {
		m = reader(t)
		m.conversation.ClientData = core.DataFragments{fragment(append(bytes.Clone(a), a[:tail]...), 7, false)}
		got = records(m)
		if len(got) != 1+min(tail, 1) {
			t.Fatalf("tail %d: %v", tail, got)
		}
		if tail > 0 && (!isLoss(got[1], 0, "tcp") || got[1].Timestamp != 7) {
			t.Fatalf("truncated tail: %v", got)
		}
	}
}

func TestLossMarkersAreBoundedAndDirectional(t *testing.T) {
	m := reader(t)
	a := wire(1, 3, 0, 1, 0, 2)
	first, second := fragment(nil, 20, false), fragment(nil, 30, false)
	first.SkippedBytes, second.SkippedBytes = 5, 7
	m.conversation.ClientData = core.DataFragments{
		fragment(a[:5], 10, false), first, second, fragment(a, 40, false),
	}
	m.conversation.ServerData = core.DataFragments{
		fragment(wire(2, 3, 2, 0, 1), 15, true), fragment(wire(3, 3, 2, 0, 1), 50, true),
	}
	got := records(m)
	// Back to back gaps are one loss event reporting the extent of the whole
	// run, and the server direction decodes across it untouched.
	if len(got) != 4 || countLoss(got) != 1 {
		t.Fatalf("got %v", got)
	}
	if !isLoss(got[1], 12, "tcp") || got[1].Timestamp != 20 || got[1].SrcIP != "192.0.2.1" {
		t.Fatalf("loss marker: %v", got[1])
	}
	if got[0].TransactionID != 2 || got[2].TransactionID != 1 || got[2].Timestamp != 40 || got[3].TransactionID != 3 {
		t.Fatalf("resumed and unaffected directions: %v", got)
	}
	// A contributing gap of unknown extent makes the whole event unknown.
	m = reader(t)
	known, unknown := fragment(nil, 20, false), fragment(nil, 30, false)
	known.SkippedBytes, unknown.SkippedBytes = 5, -1
	m.conversation.ClientData = core.DataFragments{fragment(a, 10, false), known, unknown, fragment(a, 40, false)}
	got = records(m)
	if len(got) != 2 || got[0].TransactionID != 1 || !isLoss(got[1], -1, "tcp") || got[1].Timestamp != 20 {
		t.Fatalf("unknown extent: %v", got)
	}
}

// A gap does not end on an ADU boundary just because the bytes after it pass
// the MBAP header check: protocol ID zero and a plausible length occur all over
// ordinary register data.
func TestResumeRejectsUnparsableADU(t *testing.T) {
	m := reader(t)
	gap := fragment(nil, 2, false)
	gap.SkippedBytes = 8
	// Registers 0000 0000 0005 0003 000a read as transaction 0, protocol 0,
	// length 5, unit 0 and a four byte PDU that is not a Modbus message.
	body := []byte{0, 0, 0, 0, 0, 5, 0, 3, 0, 0x0a, 0, 0, 0, 0}
	m.conversation.ClientData = core.DataFragments{
		fragment(wire(1, 3, 0, 1, 0, 2), 1, false), gap, fragment(body, 3, false),
	}
	got := records(m)
	if len(got) != 2 || got[0].TransactionID != 1 || !isLoss(got[1], 8, "tcp") || got[1].Timestamp != 2 {
		t.Fatalf("fabricated ADU after resume: %v", got)
	}
}

// A direction that accepted an initial-loss marker has started, so a later
// marker interrupts it rather than starting it again, as RTU already had it.
func TestSecondInitialLossStopsDirection(t *testing.T) {
	m := reader(t)
	decoderconfig.Instance.AllowMissingInit = true
	first, second := fragment(nil, 1, false), fragment(nil, 2, false)
	first.SkippedBytes, second.SkippedBytes = -1, -1
	m.conversation.ClientData = core.DataFragments{first, second, fragment(wire(1, 3, 0, 1, 0, 2), 3, false)}
	got := records(m)
	if len(got) != 1 || !isLoss(got[0], -1, "tcp") || got[0].Timestamp != 2 {
		t.Fatalf("second initial marker: %v", got)
	}
}

func TestMalformedAndPayloadLimits(t *testing.T) {
	m := reader(t)
	for _, length := range []int{0, 1, 255, 65535} {
		bad := wire(1, 7)
		bad[4], bad[5] = byte(length>>8), byte(length)
		if r, n := m.parseModbusMessage(bad); r != nil || n != 0 {
			t.Fatalf("invalid length %d: %v %d", length, r, n)
		}
		m.conversation.ClientData = core.DataFragments{fragment(append(bad, wire(2, 7)...), 1, false), fragment(wire(3, 7), 2, false)}
		// An unusable header is reported once, and no later fragment boundary
		// is treated as a resume point.
		got := records(m)
		if len(got) != 1 || !isLoss(got[0], 0, "tcp") || got[0].Timestamp != 1 {
			t.Fatalf("resynchronized after invalid length %d: %v", length, got)
		}
	}
	bad := wire(1, 7)
	bad[3] = 1
	if r, n := m.parseModbusMessage(bad); r != nil || n != 0 {
		t.Fatal("accepted non-Modbus protocol ID")
	}
	m.conversation.ClientData = core.DataFragments{fragment(append(bad, wire(2, 7)...), 1, false)}
	m.conversation.ServerData = core.DataFragments{fragment(wire(3, 7), 2, true)}
	got := records(m)
	if len(got) != 2 || !isLoss(got[0], 0, "tcp") || got[0].SrcIP != "192.0.2.1" || got[1].TransactionID != 3 {
		t.Fatalf("invalid header direction isolation: %v", got)
	}
	// An incomplete outer ADU must not expose a plausible nested MBAP header.
	outer := wire(1, bytes.Repeat([]byte{0xff}, 30)...)
	copy(outer[8:], wire(2, 7))
	m.conversation.ServerData = nil
	m.conversation.ClientData = core.DataFragments{fragment(outer[:20], 1, false)}
	if got := records(m); len(got) != 1 || !isLoss(got[0], 0, "tcp") {
		t.Fatalf("scanned incomplete body: %v", got)
	}
	for n := 0; n < len(outer); n++ {
		if r, consumed := m.parseModbusMessage(outer[:n]); r != nil || consumed != 0 {
			t.Fatalf("truncation %d: %v", n, r)
		}
	}
	pdu := bytes.Repeat([]byte{0x41}, maxPDUSize)
	for _, include := range []bool{true, false} {
		decoderconfig.Instance.IncludePayloads = include
		m.conversation.ClientData = core.DataFragments{fragment(wire(4, pdu...), 1, false)}
		got := records(m)
		if len(got) != 1 || got[0].Length != 254 || got[0].FunctionCode != 0x41 || (include && !bytes.Equal(got[0].Payload, pdu)) || (!include && got[0].Payload != nil) {
			t.Fatalf("max PDU/payload setting %t: %v", include, got)
		}
	}
	decoderconfig.Instance.IncludePayloads = true
	maximum := wire(4, pdu...)
	for split := 0; split <= len(maximum); split++ {
		m.conversation.ClientData = nil
		m.conversation.ServerData = core.DataFragments{fragment(maximum[:split], 1, true), fragment(maximum[split:], 2, true)}
		if got := records(m); len(got) != 1 || !bytes.Equal(got[0].Payload, pdu) || got[0].SrcPort != 502 {
			t.Fatalf("maximum ADU split %d: %v", split, got)
		}
	}
}

func TestAllowMissingInit(t *testing.T) {
	for _, allow := range []bool{false, true} {
		for _, server := range []bool{false, true} {
			for _, fallback := range []bool{false, true} {
				for _, scenario := range []string{"empty initial", "payload initial", "invalid boundary", "positive initial", "partial midstream", "complete midstream"} {
					t.Run(fmt.Sprintf("allow=%t/server=%t/fallback=%t/%s", allow, server, fallback, scenario), func(t *testing.T) {
						m := reader(t)
						decoderconfig.Instance.AllowMissingInit = allow
						a := wire(1, 3, 0, 1, 0, 2)
						gap := fragment(nil, 2, server)
						gap.SkippedBytes = -1
						affected := core.DataFragments{gap}
						// Counts hold the decoded ADUs plus the loss markers;
						// the other direction always contributes one record.
						want, loss := 1, 1
						switch scenario {
						case "empty initial":
							if allow {
								want, loss = want+1, 0
							}
						case "payload initial":
							gap.RawData = a[:4]
							a = a[4:]
							if allow {
								want, loss = want+1, 0
							}
						case "invalid boundary":
							bad := wire(9, 7)
							bad[3] = 1
							a = append(bad, a...)
						case "positive initial":
							// A known gap resumes at the first byte after it.
							gap.SkippedBytes = 1
							want++
						case "partial midstream":
							affected = core.DataFragments{fragment(a[:4], 1, server), gap}
							a = a[4:]
						case "complete midstream":
							affected = core.DataFragments{fragment(a, 1, server), gap}
							want++
						}
						want += loss
						affected = append(affected, fragment(a, 3, server))
						other := fragment(wire(2, 7), 4, !server)
						if fallback {
							m.conversation.Data = append(affected, other)
						} else if server {
							m.conversation.ServerData = affected
							m.conversation.ClientData = core.DataFragments{other}
						} else {
							m.conversation.ClientData = affected
							m.conversation.ServerData = core.DataFragments{other}
						}
						got := records(m)
						if len(got) != want || got[len(got)-1].TransactionID != 2 {
							t.Fatalf("want %d records ending with opposite direction: %v", want, got)
						}
						if countLoss(got) != loss {
							t.Fatalf("want %d loss markers: %v", loss, got)
						}
					})
				}
			}
		}
	}
}

type testWriter struct {
	netio.AuditRecordWriter
	calls int
	err   error
}

func (w *testWriter) Write(proto.Message) error { w.calls++; return w.err }

func TestDecodeWriter(t *testing.T) {
	m := reader(t)
	m.conversation.ClientData = core.DataFragments{fragment(wire(1, 7), 1, false)}
	oldWriter, oldCount := Decoder.Writer, Decoder.NumRecordsWritten
	t.Cleanup(func() { Decoder.Writer, Decoder.NumRecordsWritten = oldWriter, oldCount })
	Decoder.Writer = nil
	m.Decode()
	for _, err := range []error{nil, errors.New("write failed")} {
		w := &testWriter{err: err}
		Decoder.Writer, Decoder.NumRecordsWritten = w, 0
		m.Decode()
		want := int64(1)
		if err != nil {
			want = 0
		}
		if w.calls != 1 || Decoder.NumRecordsWritten != want {
			t.Fatalf("calls=%d count=%d", w.calls, Decoder.NumRecordsWritten)
		}
	}
}

func TestDecodeMetrics(t *testing.T) {
	registry := prometheus.NewRegistry()
	registry.MustRegister(types.Metrics...)
	count := func() float64 {
		t.Helper()
		families, err := registry.Gather()
		if err != nil {
			t.Fatal(err)
		}
		var total float64
		for _, family := range families {
			if family.GetName() == strings.ToLower(types.Type_NC_Modbus.String()) {
				for _, metric := range family.Metric {
					total += metric.GetCounter().GetValue()
				}
			}
		}
		return total
	}
	for _, enabled := range []bool{false, true} {
		for _, writeErr := range []error{nil, errors.New("write failed")} {
			t.Run(fmt.Sprintf("enabled=%t/error=%v", enabled, writeErr), func(t *testing.T) {
				m := reader(t)
				decoderconfig.Instance.ExportMetrics = enabled
				m.conversation.ClientData = core.DataFragments{fragment(append(wire(1, 3), wire(2, 3)...), 1, false)}
				m.conversation.ServerData = core.DataFragments{fragment(wire(3, 0x83, 2), 2, true)}
				oldWriter, oldCount := Decoder.Writer, Decoder.NumRecordsWritten
				t.Cleanup(func() { Decoder.Writer, Decoder.NumRecordsWritten = oldWriter, oldCount })
				w := &testWriter{err: writeErr}
				Decoder.Writer = w
				before := count()
				m.Decode()
				want := float64(0)
				if enabled {
					want = 3
				}
				if delta := count() - before; delta != want || w.calls != 3 {
					t.Fatalf("metric delta=%v want=%v writes=%d", delta, want, w.calls)
				}
			})
		}
	}
}
