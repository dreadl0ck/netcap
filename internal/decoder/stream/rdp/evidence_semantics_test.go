package rdp

import (
	"encoding/binary"
	"github.com/dreadl0ck/netcap/types"
	"testing"
)

func negotiationWire(typ byte, value uint32) []byte {
	b := []byte{typ, 0, 8, 0, 0, 0, 0, 0}
	binary.LittleEndian.PutUint32(b[4:], value)
	return b
}

func TestNegotiationIsNotAuthentication(t *testing.T) {
	r := &rdpReader{}
	for _, selected := range []uint32{ProtocolRDP, ProtocolSSL, ProtocolHybrid, ProtocolRDSTLS, ProtocolHybridEx} {
		msg := &types.RDP{}
		r.parseNegotiationRequest(msg, negotiationWire(RDPNegReq, ProtocolSSL|ProtocolHybrid))
		if msg.UsesTLS || msg.UsesNLA || msg.NegotiatedSecurityKnown {
			t.Fatal("client offer became negotiated security")
		}
		r.parseNegotiationResponse(msg, negotiationWire(RDPNegRsp, selected))
		if msg.NegotiationOutcome != "accepted" || msg.AuthenticationOutcome != "unknown" || !msg.NegotiatedSecurityKnown {
			t.Fatalf("unknown login manufactured: %+v", msg)
		}
		if msg.UsesTLS != (selected != ProtocolRDP) || msg.UsesNLA != (selected == ProtocolHybrid || selected == ProtocolHybridEx) {
			t.Fatalf("security derived from offer not selection: %+v", msg)
		}
		if !msg.ConnectionSuccessful {
			t.Fatal("legacy negotiation acceptance changed without migration")
		}
		r.parseNegotiationFailure(msg, negotiationWire(RDPNegFailure, 1))
		if msg.NegotiationOutcome != "rejected" || msg.AuthenticationOutcome != "unknown" || msg.UsesTLS || msg.UsesNLA || msg.ConnectionSuccessful || msg.NegotiatedSecurityKnown {
			t.Fatalf("rejection became auth failure/success: %+v", msg)
		}
	}
	msg := &types.RDP{}
	r.enrichWithServerResponse(msg, nil)
	if msg.NegotiationOutcome != "not-observed" || msg.AuthenticationOutcome != "unknown" {
		t.Fatal("missing negotiation is not unknown", msg)
	}
	for _, b := range [][]byte{{2}, {2, 0, 9, 0, 1, 0, 0, 0}, negotiationWire(RDPNegRsp, 3)} {
		m := &types.RDP{}
		r.parseNegotiationResponse(m, b)
		if m.NegotiationOutcome != "malformed" || m.NegotiatedSecurityKnown {
			t.Fatal("malformed response accepted", m)
		}
	}
}

func FuzzNegotiationEvidence(f *testing.F) {
	f.Add(negotiationWire(RDPNegRsp, ProtocolSSL))
	f.Add([]byte{2})
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 65536 {
			return
		}
		r := &rdpReader{}
		m := &types.RDP{}
		r.parseNegotiationRequest(m, b)
		r.parseNegotiationResponse(m, b)
		r.parseNegotiationFailure(m, b)
		r.enrichWithServerResponse(m, b)
		if m.AuthenticationOutcome != "unknown" {
			t.Fatal("negotiation manufactured authentication evidence")
		}
	})
}
