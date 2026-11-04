package ldap

import (
	"bytes"
	"github.com/dreadl0ck/netcap/internal/decoder/core"
	"github.com/dreadl0ck/netcap/types"
	"testing"
)

func tlv(tag byte, body ...byte) []byte { return append([]byte{tag, byte(len(body))}, body...) }
func entry() []byte {
	attr := tlv(0x30, append(tlv(4, []byte("displayName")...), tlv(0x31, tlv(4, []byte("Test Analyst")...)...)...)...)
	body := append(tlv(4, []byte("CN=Test,DC=example,DC=test")...), tlv(0x30, attr...)...)
	return tlv(0x30, append([]byte{2, 1, 7}, tlv(0x64, body...)...)...)
}
func TestLDAPSearchEntryAcrossEverySplit(t *testing.T) {
	wire := entry()
	if !Decoder.CanDecode(nil, wire) {
		t.Fatal("entry not recognized")
	}
	for split := 1; split < len(wire); split++ {
		r := &reader{conversation: &core.ConversationInfo{Data: core.DataFragments{&core.StreamData{RawData: wire[:split]}, &core.StreamData{RawData: wire[split:]}}}}
		var records []*types.LDAP
		r.decode(func(m *types.LDAP) { records = append(records, m) })
		if len(records) != 1 || records[0].MessageID != 7 || records[0].Operation != "SearchResultEntry" || len(records[0].Attributes) != 1 || !bytes.Equal(records[0].Attributes[0].Values[0], []byte("Test Analyst")) {
			t.Fatalf("split %d: %v", split, records)
		}
	}
}
func TestLDAPBoundsGapsAndCoalescing(t *testing.T) {
	for _, bad := range [][]byte{{0x30, 0x80}, {0x30, 0x84, 1, 0, 0, 0}, []byte("GET / HTTP/1.1\r\n"), {0x30, 5, 2, 1, 1, 0x60, 0}} {
		if Decoder.CanDecode(bad, nil) {
			t.Fatalf("claimed %x", bad)
		}
	}
	wire := entry()
	r := &reader{conversation: &core.ConversationInfo{Data: core.DataFragments{&core.StreamData{RawData: wire[:5]}, &core.StreamData{RawData: wire[5:], SkippedBytes: 1}}}}
	n := 0
	r.decode(func(*types.LDAP) { n++ })
	if n != 0 {
		t.Fatal("fabricated entry across gap")
	}
	r.conversation.Data = core.DataFragments{&core.StreamData{RawData: append(append([]byte(nil), wire...), wire...)}}
	r.decode(func(*types.LDAP) { n++ })
	if n != 2 {
		t.Fatal("lost coalesced entry", n)
	}
}
