package dcerpc

import (
	"encoding/binary"
	"testing"
	"time"

	"github.com/gopacket/gopacket"

	"github.com/dreadl0ck/netcap/internal/decoder/core"
	"github.com/dreadl0ck/netcap/internal/reassembly"
	"github.com/dreadl0ck/netcap/types"
)

const (
	uuidSVCCTL = "367abb81-9844-35f1-ad32-98f038001003"
	uuidSAMR   = "12345778-1234-abcd-ef00-0123456789ac"
)

func rawUUID(s string) []byte {
	var hexDigits []byte
	for i := 0; i < len(s); i++ {
		if s[i] != '-' {
			hexDigits = append(hexDigits, s[i])
		}
	}
	b := make([]byte, 16)
	for i := range b {
		var v byte
		for _, c := range hexDigits[2*i : 2*i+2] {
			v <<= 4
			if c >= 'a' {
				v |= c - 'a' + 10
			} else {
				v |= c - '0'
			}
		}
		b[i] = v
	}
	// Little-endian data representation: swap the first three fields.
	b[0], b[1], b[2], b[3] = b[3], b[2], b[1], b[0]
	b[4], b[5] = b[5], b[4]
	b[6], b[7] = b[7], b[6]
	return b
}

func pdu(ptype, flags byte, callID uint32, body []byte) []byte {
	h := make([]byte, 16, 16+len(body))
	h[0], h[1], h[2], h[3], h[4] = 5, 0, ptype, flags, 0x10
	binary.LittleEndian.PutUint16(h[8:], uint16(16+len(body)))
	binary.LittleEndian.PutUint32(h[12:], callID)
	return append(h, body...)
}

func bind(callID uint32, contexts ...string) []byte {
	body := []byte{0xb8, 0x10, 0xb8, 0x10, 0, 0, 0, 0, byte(len(contexts)), 0, 0, 0}
	for i, uuid := range contexts {
		item := []byte{byte(i), 0, 1, 0}
		item = append(item, rawUUID(uuid)...)
		item = append(item, 2, 0, 0, 0)          // interface version
		item = append(item, make([]byte, 20)...) // one transfer syntax
		body = append(body, item...)
	}
	return pdu(ptypeBind, 3, callID, body)
}

func request(callID uint32, ctx, opnum uint16) []byte {
	body := make([]byte, 8, 12)
	binary.LittleEndian.PutUint16(body[4:], ctx)
	binary.LittleEndian.PutUint16(body[6:], opnum)
	return pdu(ptypeRequest, 3, callID, append(body, 1, 2, 3, 4))
}

func response(ptype byte, callID uint32, ctx uint16, status uint32) []byte {
	body := make([]byte, 12)
	binary.LittleEndian.PutUint16(body[4:], ctx)
	binary.LittleEndian.PutUint32(body[8:], status)
	return pdu(ptype, 3, callID, body)
}

func fragment(data []byte, ts int64, server bool) *core.StreamData {
	d := &core.StreamData{RawData: data, CaptureInformation: gopacket.CaptureInfo{Timestamp: time.Unix(0, ts)}}
	if server {
		d.Dir = reassembly.TCPDirServerToClient
	}
	return d
}

func cat(parts ...[]byte) (out []byte) {
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

func decodeAll(conv *core.ConversationInfo) (out []*types.DCERPC) {
	(&dcerpcReader{conversation: conv}).decode(func(r *types.DCERPC) { out = append(out, r) })
	return out
}

func TestRequestsCarryInterfaceAndOperationAcrossSplits(t *testing.T) {
	client := cat(bind(1, uuidSVCCTL, uuidSAMR), request(2, 0, 12), request(3, 1, 64), request(4, 0, 19))
	server := cat(response(ptypeResponse, 2, 0, 0), response(ptypeFault, 4, 0, 5), response(ptypeResponse, 3, 1, 0))
	for split := 0; split <= len(client); split++ {
		conv := &core.ConversationInfo{
			ClientIP: "192.0.2.1", ServerIP: "192.0.2.2", ClientPort: 50000, ServerPort: 135, CommunityID: "1:cid", Ident: "flow",
			ClientData: core.DataFragments{fragment(client[:split], 100, false), fragment(client[split:], 200, false)},
			ServerData: core.DataFragments{fragment(server, 300, true)},
		}
		got := decodeAll(conv)
		if len(got) != 7 {
			t.Fatalf("split %d: %d records", split, len(got))
		}
		want := []struct {
			ptype, iface, op string
			opnum            int32
			status           uint32
		}{
			{"Bind", "SVCCTL", "", 0, 0},
			{"Request", "SVCCTL", "RCreateServiceW", 12, 0},
			{"Request", "SAMR", "SamrConnect5", 64, 0},
			{"Request", "SVCCTL", "RStartServiceW", 19, 0},
			{"Response", "SVCCTL", "RCreateServiceW", 12, 0},
			{"Fault", "SVCCTL", "RStartServiceW", 19, 5},
			{"Response", "SAMR", "SamrConnect5", 64, 0},
		}
		for i, w := range want {
			r := got[i]
			if r.PacketTypeName != w.ptype || r.InterfaceName != w.iface || r.OperationName != w.op || r.OpNum != w.opnum || r.FaultStatus != w.status || r.CommunityID != "1:cid" {
				t.Fatalf("split %d record %d: %+v", split, i, r)
			}
		}
		if got[6].SrcIP != "192.0.2.2" || got[6].SrcPort != 135 || got[1].SrcIP != "192.0.2.1" || got[4].Timestamp != 300 {
			t.Fatalf("split %d direction/time: %+v %+v", split, got[1], got[6])
		}
	}
}

func TestUnknownContextAndTruncation(t *testing.T) {
	conv := &core.ConversationInfo{ClientData: core.DataFragments{fragment(cat(request(9, 7, 12), request(10, 0, 1)[:20]), 1, false)}}
	got := decodeAll(conv)
	if len(got) != 1 || got[0].InterfaceName != "" || got[0].OperationName != "" || got[0].OpNum != 12 || got[0].ContextID != 7 {
		t.Fatalf("request without a learned context must stay unattributed, truncated PDU dropped: %+v", got)
	}
	// An unanswered response keeps the context's interface but no operation.
	conv = &core.ConversationInfo{
		ClientData: core.DataFragments{fragment(bind(1, uuidSVCCTL), 1, false)},
		ServerData: core.DataFragments{fragment(response(ptypeResponse, 77, 0, 0), 2, true)},
	}
	got = decodeAll(conv)
	if len(got) != 2 || got[1].InterfaceName != "SVCCTL" || got[1].OperationName != "" {
		t.Fatalf("unsolicited response: %+v", got)
	}
}

func TestMergedDataFallbackSplitsDirections(t *testing.T) {
	conv := &core.ConversationInfo{Data: core.DataFragments{
		fragment(bind(1, uuidSAMR), 1, false),
		fragment(response(ptypeResponse, 5, 0, 0), 2, true),
		fragment(request(5, 0, 7), 3, false),
	}}
	got := decodeAll(conv)
	if len(got) != 3 || got[1].OperationName != "" || got[2].OperationName != "SamrOpenDomain" {
		t.Fatalf("merged fallback: %+v", got)
	}
}

func TestContextChangesDoNotRewriteEarlierCalls(t *testing.T) {
	changed := bind(3, uuidSAMR)
	changed[2] = ptypeAlterContext
	conv := &core.ConversationInfo{Data: core.DataFragments{
		fragment(bind(1, uuidSVCCTL), 10, false),
		fragment(request(2, 0, 12), 20, false),
		fragment(changed, 30, false),
		fragment(response(ptypeResponse, 2, 0, 0), 40, true),
	}}
	got := decodeAll(conv)
	if got[3].InterfaceName != "SVCCTL" || got[3].OperationName != "RCreateServiceW" {
		t.Fatalf("later binding rewrote earlier call: %+v", got[3])
	}
}

func TestNoFramingOrAttributionAcrossStreamGap(t *testing.T) {
	a := request(2, 0, 12)
	gap := fragment(a[20:], 30, false)
	gap.SkippedBytes = 1
	conv := &core.ConversationInfo{Data: core.DataFragments{
		fragment(bind(1, uuidSVCCTL), 10, false),
		fragment(a[:20], 20, false), gap,
		fragment(request(3, 0, 19), 40, false),
	}}
	got := decodeAll(conv)
	if len(got) != 2 || got[1].InterfaceName != "" || got[1].OperationName != "" {
		t.Fatalf("gap retained context or joined bytes: %+v", got)
	}
}

func TestPendingCallsAreBounded(t *testing.T) {
	var client []byte
	client = append(client, bind(1, uuidSVCCTL)...)
	for i := 0; i < maxPendingCalls+10; i++ {
		client = append(client, request(uint32(i+2), 0, 12)...)
	}
	r := &dcerpcReader{conversation: &core.ConversationInfo{ClientData: core.DataFragments{fragment(client, 1, false)}}}
	n := 0
	r.decode(func(*types.DCERPC) { n++ })
	if n != maxPendingCalls+11 || r.pending != maxPendingCalls {
		t.Fatalf("records=%d pending=%d", n, r.pending)
	}
}
