package ldap

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/dreadl0ck/netcap/internal/decoder/core"
	"github.com/dreadl0ck/netcap/types"
)

func saslFrame(token []byte) []byte {
	wire := make([]byte, 4, len(token)+4)
	binary.BigEndian.PutUint32(wire, uint32(len(token)))
	return append(wire, token...)
}

func TestSASLIntegrityFramesAcrossEverySplit(t *testing.T) {
	for _, mechanism := range []string{"ntlm", "kerberos"} {
		t.Run(mechanism, func(t *testing.T) {
			header := make([]byte, 16)
			if mechanism == "ntlm" {
				binary.LittleEndian.PutUint32(header, 1)
			} else {
				header[0], header[1], header[3] = 5, 4, 255
			}
			wire := saslFrame(append(header, entry()...))
			wire = append(wire, wire...)
			for split := 1; split < len(wire); split++ {
				r := &reader{saslActive: true, ntlmKnown: true, conversation: &core.ConversationInfo{Data: core.DataFragments{&core.StreamData{RawData: wire[:split]}, &core.StreamData{RawData: wire[split:]}}}}
				var records []*types.LDAP
				r.decode(func(m *types.LDAP) { records = append(records, m) })
				if len(records) != 2 || records[0].ReassemblyStatus != "sasl-integrity-not-verified" || !bytes.Equal(records[1].Attributes[0].Values[0], []byte("Test Analyst")) {
					t.Fatalf("split %d: %v", split, records)
				}
			}
		})
	}
}

func TestSASLRefusesSealedOrUnnegotiatedNTLM(t *testing.T) {
	token := append(make([]byte, 16), entry()...)
	binary.LittleEndian.PutUint32(token, 1)
	for _, mode := range [][2]bool{{false, false}, {true, true}} {
		if plain, _ := unwrapSASL(token, mode[0], mode[1]); plain != nil {
			t.Fatal("decoded an unknown or sealed NTLM payload")
		}
	}
	token[0], token[1], token[2], token[3] = 5, 4, 2, 255
	if plain, _ := unwrapSASL(token, true, false); plain != nil {
		t.Fatal("decoded a sealed Kerberos payload")
	}
}

func TestSASLKerberosRotationAndChecksum(t *testing.T) {
	header := make([]byte, 16)
	header[0], header[1], header[3] = 5, 4, 255
	binary.BigEndian.PutUint16(header[4:6], 12)
	binary.BigEndian.PutUint16(header[6:8], 7)
	body := append(append([]byte(nil), entry()...), make([]byte, 12)...)
	body = append(append([]byte(nil), body[len(body)-7:]...), body[:len(body)-7]...)
	plain, _ := unwrapSASL(append(header, body...), false, false)
	if !bytes.Equal(plain, entry()) {
		t.Fatalf("rotation or checksum removal corrupted LDAP: %x", plain)
	}
	header[4], header[5] = 255, 255
	if plain, _ := unwrapSASL(append(header, body...), false, false); plain != nil {
		t.Fatal("accepted checksum length beyond token")
	}
}

func TestSASLBindNegotiation(t *testing.T) {
	credential := make([]byte, 64)
	copy(credential, "NTLMSSP\x00")
	binary.LittleEndian.PutUint32(credential[8:], 3)
	binary.LittleEndian.PutUint32(credential[60:], 0x10)
	auth := append(tlv(4, []byte("GSS-SPNEGO")...), tlv(4, credential...)...)
	bind := tlv(0x30, append([]byte{2, 1, 1}, tlv(0x60, append([]byte{2, 1, 3, 4, 0}, tlv(0xa3, auth...)...)...)...)...)
	response := tlv(0x30, append([]byte{2, 1, 1}, tlv(0x61, 10, 1, 0, 4, 0, 4, 0)...)...)
	token := append(make([]byte, 16), entry()...)
	binary.LittleEndian.PutUint32(token, 1)
	r := &reader{conversation: &core.ConversationInfo{Data: core.DataFragments{&core.StreamData{RawData: bind}, &core.StreamData{RawData: response}, &core.StreamData{RawData: saslFrame(token)}}}}
	var records []*types.LDAP
	r.decode(func(m *types.LDAP) { records = append(records, m) })
	if len(records) != 3 || records[0].AuthMechanism != "GSS-SPNEGO" || records[0].SASLNTLMFlags != 0x10 || records[2].Operation != "SearchResultEntry" {
		t.Fatalf("negotiation failed: %v", records)
	}
}

func TestLDAPMessageAcrossSASLFrames(t *testing.T) {
	message := entry()
	for split := 1; split < len(message); split++ {
		var wire []byte
		for _, piece := range [][]byte{message[:split], message[split:]} {
			header := make([]byte, 16)
			binary.LittleEndian.PutUint32(header, 1)
			wire = append(wire, saslFrame(append(header, piece...))...)
		}
		r := &reader{saslActive: true, ntlmKnown: true, conversation: &core.ConversationInfo{Data: core.DataFragments{&core.StreamData{RawData: wire}}}}
		var records []*types.LDAP
		r.decode(func(m *types.LDAP) { records = append(records, m) })
		if len(records) != 1 || records[0].Operation != "SearchResultEntry" {
			t.Fatalf("split %d: %v", split, records)
		}
	}
}
