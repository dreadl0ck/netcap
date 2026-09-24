/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package dnp3

import (
	"encoding/binary"
	"encoding/hex"
	"testing"
	"time"

	"github.com/gopacket/gopacket"

	"github.com/dreadl0ck/netcap/internal/decoder/core"
	"github.com/dreadl0ck/netcap/internal/reassembly"
	"github.com/dreadl0ck/netcap/types"
)

// Real frames from tests/ICS-pcap/DNP3, kept as hex so the CRCs are the ones a
// device produced rather than ones this package computed.
const (
	frameSelect   = "05641ac403000400c9b7c1c1030c0128010001000301640000007b5e6400000000005b"
	frameOperate  = "05641ac403000400c9b7c1c2040c01280100010003016400000083546400000000005b"
	frameRead     = "05640bc403000400ef7ac1c1013c0206b576"
	frameWrite    = "056412c403000400152dc1c10232010701fa7d0b460d01c863"
	frameLinkReq  = "056405c903000400bd71"
	frameFuzzHead = "056402c40a00010097fe" // LENGTH 2, below the protocol minimum
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()

	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}

	return b
}

func fragment(data []byte, timestamp int64, server bool, skipped int) *core.StreamData {
	d := &core.StreamData{
		RawData:            data,
		SkippedBytes:       skipped,
		CaptureInformation: gopacket.CaptureInfo{Timestamp: time.Unix(0, timestamp)},
	}
	if server {
		d.Dir = reassembly.TCPDirServerToClient
	}

	return d
}

func reader(client, server core.DataFragments, handshake bool) *dnp3Reader {
	return &dnp3Reader{conversation: &core.ConversationInfo{
		ClientData: client, ServerData: server,
		ClientIP: "192.0.2.1", ServerIP: "192.0.2.2",
		ClientPort: 12345, ServerPort: 20000,
		CommunityID:          "community",
		TCPHandshakeComplete: handshake,
		FirstClientPacket:    time.Unix(99, 0),
	}}
}

func records(d *dnp3Reader) (out []*types.DNP3) {
	d.frameConversation(func(r *types.DNP3) { out = append(out, r) })

	return
}

func valid(records []*types.DNP3) (out []*types.DNP3) {
	for _, r := range records {
		if r.ParseStatus == statusValid {
			out = append(out, r)
		}
	}

	return
}

func TestFrameLenIncludesBlockCRCs(t *testing.T) {
	for _, tt := range []struct {
		length byte
		want   int
	}{
		{5, 10},    // header only
		{6, 13},    // 1 user octet + 1 block CRC
		{21, 28},   // 16 user octets, exactly one block
		{22, 31},   // 17 user octets, two blocks
		{26, 35},   // the select frame
		{255, maxFrameLen}, // the largest frame the length octet can express
	} {
		if got := frameLen(tt.length); got != tt.want {
			t.Errorf("frameLen(%d) = %d, want %d", tt.length, got, tt.want)
		}
	}

	// Below the protocol minimum there is no frame to size.
	for _, length := range []byte{0, 1, 4} {
		if got := frameLen(length); got != -1 {
			t.Errorf("frameLen(%d) = %d, want -1", length, got)
		}
	}
}

// The wire length must match the bytes a device actually sent, or the scan
// resumes inside the previous frame's payload.
func TestFrameLenMatchesCapturedFrames(t *testing.T) {
	for _, s := range []string{frameSelect, frameOperate, frameRead, frameWrite, frameLinkReq} {
		b := mustHex(t, s)
		if got := frameLen(b[2]); got != len(b) {
			t.Errorf("frameLen = %d, captured frame is %d bytes", got, len(b))
		}
	}
}

func TestDecodesSelectAndOperate(t *testing.T) {
	client := core.DataFragments{
		fragment(mustHex(t, frameSelect), 1000, false, 0),
		fragment(mustHex(t, frameOperate), 2000, false, 0),
	}

	got := valid(records(reader(client, nil, true)))
	if len(got) != 2 {
		t.Fatalf("got %d valid records, want 2", len(got))
	}

	if got[0].FunctionCodeName != "SELECT" || got[1].FunctionCodeName != "OPERATE" {
		t.Fatalf("function codes = %q, %q", got[0].FunctionCodeName, got[1].FunctionCodeName)
	}
	if !got[1].IsCriticalFunction {
		t.Error("OPERATE is not flagged critical")
	}
	if got[0].LinkFunctionCodeName != "UNCONFIRMED_USER_DATA" {
		t.Errorf("link function = %q", got[0].LinkFunctionCodeName)
	}
	if !got[0].HeaderCRCValid || !got[0].BlockCRCValid {
		t.Error("CRCs not reported valid on a genuine frame")
	}
}

// Each frame is timestamped from the packet that carried it. A conversation
// held open for days otherwise reports one instant for every command in it.
func TestPerFrameTimestamps(t *testing.T) {
	client := core.DataFragments{
		fragment(mustHex(t, frameSelect), 1000, false, 0),
		fragment(mustHex(t, frameOperate), 5000, false, 0),
	}

	got := valid(records(reader(client, nil, true)))
	if len(got) != 2 {
		t.Fatalf("got %d records, want 2", len(got))
	}
	if got[0].Timestamp != 1000 || got[1].Timestamp != 5000 {
		t.Errorf("timestamps = %d, %d; want 1000, 5000", got[0].Timestamp, got[1].Timestamp)
	}
}

// Two frames arriving in one packet share that packet's capture time, and the
// second must not inherit the conversation's first packet instead.
func TestTimestampsWithinOneFragment(t *testing.T) {
	both := append(mustHex(t, frameSelect), mustHex(t, frameOperate)...)
	got := valid(records(reader(core.DataFragments{fragment(both, 7000, false, 0)}, nil, true)))

	if len(got) != 2 {
		t.Fatalf("got %d records, want 2", len(got))
	}
	for i, r := range got {
		if r.Timestamp != 7000 {
			t.Errorf("record %d timestamp = %d, want 7000", i, r.Timestamp)
		}
	}
}

// A response must carry the outstation as SrcIP. Recording it with the master's
// address makes a reply indistinguishable from a command.
func TestDirectionAttribution(t *testing.T) {
	d := reader(
		core.DataFragments{fragment(mustHex(t, frameSelect), 1000, false, 0)},
		core.DataFragments{fragment(mustHex(t, frameSelect), 2000, true, 0)},
		true,
	)

	got := valid(records(d))
	if len(got) != 2 {
		t.Fatalf("got %d records, want 2", len(got))
	}

	if got[0].SrcIP != "192.0.2.1" || got[0].DstIP != "192.0.2.2" || got[0].SrcPort != 12345 {
		t.Errorf("client record attributed to %s:%d -> %s", got[0].SrcIP, got[0].SrcPort, got[0].DstIP)
	}
	if got[1].SrcIP != "192.0.2.2" || got[1].DstIP != "192.0.2.1" || got[1].SrcPort != 20000 {
		t.Errorf("server record attributed to %s:%d -> %s", got[1].SrcIP, got[1].SrcPort, got[1].DstIP)
	}
}

// The select frame carries DIR=1 (from the master). Seen arriving from the
// outstation's side of the connection, the link address and the IP disagree.
func TestDirectionMismatch(t *testing.T) {
	d := reader(
		core.DataFragments{fragment(mustHex(t, frameSelect), 1000, false, 0)},
		core.DataFragments{fragment(mustHex(t, frameSelect), 2000, true, 0)},
		true,
	)

	got := valid(records(d))
	if got[0].DirectionMismatch {
		t.Error("master frame from the client side reported as a mismatch")
	}
	if !got[1].DirectionMismatch {
		t.Error("master frame from the outstation side not reported as a mismatch")
	}
}

// Without a handshake the client and server assignment may be reversed, so the
// DIR bit cannot be checked against it.
func TestDirectionMismatchNeedsOrientation(t *testing.T) {
	d := reader(nil, core.DataFragments{fragment(mustHex(t, frameSelect), 1000, true, 0)}, false)

	for _, r := range valid(records(d)) {
		if r.DirectionMismatch {
			t.Error("mismatch reported without an observed handshake")
		}
	}
}

// Two matching bytes inside a payload are not a frame. Without the CRC check
// the scan emits records for control commands that were never sent.
func TestPhantomFrameRejected(t *testing.T) {
	// A start byte pair followed by plausible-looking bytes, with a wrong CRC.
	phantom := []byte{startByte1, startByte2, 0x1a, 0xc4, 0x03, 0x00, 0x04, 0x00, 0x00, 0x00}
	phantom = append(phantom, make([]byte, 40)...)

	got := valid(records(reader(core.DataFragments{fragment(phantom, 1000, false, 0)}, nil, true)))
	if len(got) != 0 {
		t.Fatalf("got %d records from a payload that contains no frame", len(got))
	}
}

// The regression this decoder was rewritten for: the select frame's own body
// contains a 0x0564 pair, and advancing by the wrong length lands on it.
func TestNoPhantomFrameInsideRealFrame(t *testing.T) {
	frame := mustHex(t, frameSelect)

	if idx := frameStart(frame, 2); idx < 0 {
		t.Skip("this frame no longer contains an embedded start byte pair")
	}

	got := valid(records(reader(core.DataFragments{fragment(frame, 1000, false, 0)}, nil, true)))
	if len(got) != 1 {
		t.Fatalf("got %d records from one frame", len(got))
	}
}

// A header that authenticates but reports a length below the minimum is a
// malformed frame from a real sender, which is evidence rather than noise.
func TestMalformedLengthReported(t *testing.T) {
	frame := append(mustHex(t, frameFuzzHead), make([]byte, 285)...)

	var malformed *types.DNP3

	for _, r := range records(reader(core.DataFragments{fragment(frame, 1000, false, 0)}, nil, true)) {
		if r.ParseStatus == statusMalformed {
			malformed = r
		}
	}

	if malformed == nil {
		t.Fatal("no malformed record emitted")
	}
	if malformed.ParseError == "" {
		t.Error("malformed record carries no reason")
	}
	if !malformed.HeaderCRCValid {
		t.Error("header CRC should be reported valid: it is what makes this a real sender")
	}
	if malformed.Source != 1 || malformed.Destination != 10 {
		t.Errorf("link addresses = %d -> %d, want 1 -> 10", malformed.Source, malformed.Destination)
	}
}

// A block CRC failure means the user data is corrupt, so no values are decoded.
func TestBlockCRCFailureSuppressesValues(t *testing.T) {
	frame := mustHex(t, frameSelect)
	frame[linkHeaderLen+16] ^= 0xFF // corrupt the first block's CRC

	got := records(reader(core.DataFragments{fragment(frame, 1000, false, 0)}, nil, true))
	if len(got) == 0 {
		t.Fatal("no record emitted")
	}

	r := got[0]
	if r.ParseStatus != statusMalformed {
		t.Fatalf("status = %q, want malformed", r.ParseStatus)
	}
	if r.BlockCRCValid {
		t.Error("block CRC reported valid")
	}
	if r.FunctionCode != 0 || len(r.Objects) != 0 {
		t.Error("corrupt user data was decoded anyway")
	}
}

// A link control frame carries link state, not an application PDU. Parsing one
// reads that state as a function code.
func TestLinkControlFrameNotParsedAsAPDU(t *testing.T) {
	got := records(reader(core.DataFragments{fragment(mustHex(t, frameLinkReq), 1000, false, 0)}, nil, true))
	if len(got) != 1 {
		t.Fatalf("got %d records, want 1", len(got))
	}

	r := got[0]
	if r.LinkFunctionCodeName != "REQUEST_LINK_STATUS" {
		t.Errorf("link function = %q", r.LinkFunctionCodeName)
	}
	if r.FunctionCode != 0 || r.FunctionCodeName != "" {
		t.Errorf("application function decoded from a link frame: %d %q", r.FunctionCode, r.FunctionCodeName)
	}
}

// A capture gap ends coverage. An empty hunt result over a gap is not evidence
// of absence, so the gap has to be a record.
func TestCaptureGapEmitsMarker(t *testing.T) {
	client := core.DataFragments{
		fragment(mustHex(t, frameSelect), 1000, false, 0),
		fragment(mustHex(t, frameOperate), 2000, false, 64),
	}

	var marker *types.DNP3

	for _, r := range records(reader(client, nil, true)) {
		if r.ParseStatus == statusLost {
			marker = r
		}
	}

	if marker == nil {
		t.Fatal("no loss marker emitted")
	}
	if marker.LostBytes != 64 {
		t.Errorf("LostBytes = %d, want 64", marker.LostBytes)
	}
	if marker.CorrelationStatus != "not_applicable" || marker.FunctionCode != 0 {
		t.Error("loss marker carries decoded fields")
	}
}

// An unknown initial gap is reported as -1, not as zero, so it cannot be read
// as a contiguous capture.
func TestUnknownInitialLoss(t *testing.T) {
	client := core.DataFragments{
		fragment(nil, 1000, false, -1),
		fragment(mustHex(t, frameSelect), 1000, false, 0),
	}

	got := records(reader(client, nil, true))
	if len(got) < 2 || got[0].ParseStatus != statusLost {
		t.Fatalf("expected a leading loss marker, got %d records", len(got))
	}
	if got[0].LostBytes != -1 {
		t.Errorf("LostBytes = %d, want -1", got[0].LostBytes)
	}
}

// A frame split across two packets still has to decode.
func TestFrameSplitAcrossFragments(t *testing.T) {
	frame := mustHex(t, frameSelect)
	client := core.DataFragments{
		fragment(frame[:12], 1000, false, 0),
		fragment(frame[12:], 2000, false, 0),
	}

	got := valid(records(reader(client, nil, true)))
	if len(got) != 1 {
		t.Fatalf("got %d records, want 1", len(got))
	}
	if got[0].FunctionCodeName != "SELECT" {
		t.Errorf("function code = %q", got[0].FunctionCodeName)
	}
	if got[0].Timestamp != 1000 {
		t.Errorf("timestamp = %d, want the first byte's packet (1000)", got[0].Timestamp)
	}
}

// A start byte pair straddling two packets must not be lost.
func TestStartBytesSplitAcrossFragments(t *testing.T) {
	frame := mustHex(t, frameSelect)
	client := core.DataFragments{
		fragment(frame[:1], 1000, false, 0),
		fragment(frame[1:], 2000, false, 0),
	}

	if got := valid(records(reader(client, nil, true))); len(got) != 1 {
		t.Fatalf("got %d records, want 1", len(got))
	}
}

// Callers that supply only the merged view still get framed output.
func TestMergedOnlyConversation(t *testing.T) {
	d := &dnp3Reader{conversation: &core.ConversationInfo{
		Data:     core.DataFragments{fragment(mustHex(t, frameSelect), 1000, false, 0)},
		ClientIP: "192.0.2.1", ServerIP: "192.0.2.2", ClientPort: 12345, ServerPort: 20000,
	}}

	if got := valid(records(d)); len(got) != 1 {
		t.Fatalf("got %d records, want 1", len(got))
	}
}

func TestBroadcastDestination(t *testing.T) {
	for _, tt := range []struct {
		dest      uint16
		broadcast bool
		self      bool
	}{
		{3, false, false},
		{0xFFFC, false, true},
		{0xFFFD, true, false},
		{0xFFFE, true, false},
		{0xFFFF, true, false},
	} {
		frame := mustHex(t, frameSelect)
		binary.LittleEndian.PutUint16(frame[4:6], tt.dest)

		crc := crc16DNP(frame[:8])
		binary.LittleEndian.PutUint16(frame[8:10], crc)

		got := valid(records(reader(core.DataFragments{fragment(frame, 1000, false, 0)}, nil, true)))
		if len(got) != 1 {
			t.Fatalf("destination %#04x: got %d records", tt.dest, len(got))
		}
		if got[0].IsBroadcast != tt.broadcast || got[0].IsSelfAddress != tt.self {
			t.Errorf("destination %#04x: broadcast=%v self=%v", tt.dest, got[0].IsBroadcast, got[0].IsSelfAddress)
		}
	}
}

func TestCanDecodeRequiresValidHeader(t *testing.T) {
	for _, tt := range []struct {
		name   string
		data   []byte
		accept bool
	}{
		{"real frame", mustHex(t, frameSelect), true},
		{"start bytes only", []byte{0x05, 0x64}, false},
		{"start bytes with bad crc", append([]byte{0x05, 0x64, 0x1a, 0xc4, 3, 0, 4, 0, 0, 0}, make([]byte, 20)...), false},
		{"empty", nil, false},
		{"no start bytes", []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"), false},
		{"frame after junk", append([]byte("junk"), mustHex(t, frameSelect)...), true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := Decoder.CanDecode(tt.data, nil); got != tt.accept {
				t.Errorf("CanDecode = %v, want %v", got, tt.accept)
			}
			if got := Decoder.CanDecode(nil, tt.data); got != tt.accept {
				t.Errorf("CanDecode (server side) = %v, want %v", got, tt.accept)
			}
		})
	}
}
