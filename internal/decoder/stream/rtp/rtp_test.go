package rtp

import (
	"encoding/binary"
	"fmt"
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/internal/decoder/core"
	"github.com/dreadl0ck/netcap/internal/sipaudit"
	"github.com/dreadl0ck/netcap/types"
	"github.com/gopacket/gopacket"
)

func TestRTPBounds(t *testing.T) {
	valid := []byte{0x80, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 1}
	if r, p := parse(valid); r == nil || len(p) != 1 || r.Sequence != 1 || r.SSRC != 3 {
		t.Fatal("valid RTP rejected")
	}
	for _, data := range [][]byte{
		valid[:11], {0x8f, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 1},
		{0xa0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 0},
		{0xa0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 2},
		{0x90, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0xff, 0xff},
		{0x80, 200, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 1},
	} {
		if r, _ := parse(data); r != nil {
			t.Fatalf("malformed RTP accepted: %x", data)
		}
	}
	withExtras := []byte{0xb1, 0x80, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, 4, 0xbe, 0xde, 0, 1, 0, 0, 0, 0, 9, 0, 0, 3}
	r, p := parse(withExtras)
	if r == nil || len(p) != 1 || p[0] != 9 || r.CSRC[0] != 4 || r.ExtensionProfile != 0xbede || r.ExtensionLength != 4 || r.PaddingLength != 3 || !r.Marker {
		t.Fatal("CSRC/extension/padding offset")
	}
}

func TestCapacityLossDoesNotIdentifyArbitraryUDPAsRTP(t *testing.T) {
	old := sipaudit.Media
	sipaudit.Media = sipaudit.NewAssociationsWithBudget(0)
	t.Cleanup(func() { sipaudit.Media = old })
	sipaudit.Media.Observe(&types.SIP{Timestamp: 1, CallID: "overflow", From: "<sip:a@example.test>;tag=a", MethodName: "BYE"})
	if sipaudit.Media.Qualification(2) == "" {
		t.Fatal("missing overflow precondition")
	}
	c := &core.ConversationInfo{Data: core.DataFragments{&core.StreamData{RawData: []byte{0x80, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 1}, CaptureInformation: gopacket.CaptureInfo{Timestamp: time.Unix(0, 2)}}}}
	if Matches(c) {
		t.Fatal("capacity loss must not turn version bits into protocol identification")
	}
}

func FuzzRTP(f *testing.F) {
	f.Add([]byte{0x80, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 1})
	f.Add([]byte{0x90, 110, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, 0, 5, 138, 0, 160})
	f.Fuzz(func(t *testing.T, data []byte) {
		r, p := parse(data)
		if r != nil && (int(r.PayloadLength) != len(p) || len(r.CSRC) > 15 || r.MediaTimestamp != binary.BigEndian.Uint32(data[4:8])) {
			t.Fatal("RTP bounds")
		}
	})
}

func TestRTPReaderRequiresSignalingScope(t *testing.T) {
	old := sipaudit.Media
	sipaudit.Media = sipaudit.NewAssociations()
	t.Cleanup(func() { sipaudit.Media = old })
	for _, answer := range []bool{false, true} {
		ip, port := "10.0.0.1", 4000
		if answer {
			ip, port = "10.0.0.2", 5000
		}
		sipaudit.Media.Observe(&types.SIP{NetworkScope: "if:1/vni:7", Timestamp: 1, CallID: "same-call", From: "<sip:a@example.test>;tag=one", CSeqNumber: 1, CSeqMethod: "INVITE", MethodName: "INVITE", IsResponse: answer, ResponseCode: 200,
			ContentType: "application/sdp", Body: []byte(fmt.Sprintf("v=0\r\nc=IN IP4 %s\r\nm=audio %d RTP/AVP 110\r\na=rtpmap:110 telephone-event/8000\r\n", ip, port))})
	}
	for _, scope := range []string{"if:1/vni:7", "if:2/vni:7", "if:1/vni:8", ""} {
		c := &core.ConversationInfo{NetworkScope: scope, ClientIP: "10.0.0.1", ServerIP: "10.0.0.2", ClientPort: 4000, ServerPort: 5000,
			Data: core.DataFragments{&core.StreamData{RawData: []byte{0x80, 110, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 5, 0x8a, 0, 160}, CaptureInformation: gopacket.CaptureInfo{Timestamp: time.Unix(0, 2)}}}}
		want := scope == "if:1/vni:7"
		if Matches(c) != want {
			t.Fatalf("scope=%q selector mismatch", scope)
		}
		packets, events := 0, 0
		(&reader{c}).decode(func(*types.RTP) { packets++ }, func(*types.DTMF) { events++ })
		if want && (packets != 1 || events != 1) || !want && (packets != 0 || events != 0) {
			t.Fatalf("scope=%q packets=%d events=%d", scope, packets, events)
		}
	}
}
