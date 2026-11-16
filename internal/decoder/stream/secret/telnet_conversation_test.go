package secret

import (
	"bytes"
	"testing"

	"github.com/dreadl0ck/netcap/internal/decoder/core"
	"github.com/dreadl0ck/netcap/internal/reassembly"
	"github.com/dreadl0ck/netcap/types"
)

func BenchmarkTelnetBinaryConversation(b *testing.B) {
	c := &core.ConversationInfo{Data: core.DataFragments{
		&core.StreamData{Dir: reassembly.TCPDirServerToClient, RawData: bytes.Repeat([]byte{0x80, 0xc0, 0xfe, 0x16}, 600)},
	}}
	b.ReportAllocs()
	b.SetBytes(2400)
	for b.Loop() {
		parseTelnetAuth(c, func(*types.Secret) { b.Fatal("binary data harvested") })
	}
}

func TestTelnetOffPortRequiresBoundedPromptEvidence(t *testing.T) {
	for _, tc := range []struct {
		wire []byte
		want bool
	}{
		{[]byte("Welcome\r\nLoGiN:"), true},
		{bytes.Repeat([]byte{0x16, 0x80, 0xc0, 0xfe}, 2048), false},
		{append(bytes.Repeat([]byte{'x'}, 4096), []byte("login:")...), false},
	} {
		c := &core.ConversationInfo{ServerPort: 443, Data: core.DataFragments{&core.StreamData{Dir: reassembly.TCPDirServerToClient, RawData: tc.wire}}}
		if telnetPromptEvidence(c) != tc.want {
			t.Fatalf("unexpected prompt classification, length %d", len(tc.wire))
		}
	}
}

func TestTelnetDirectionalCredentialsWithNULAndNegotiation(t *testing.T) {
	for _, padded := range []bool{false, true} {
		var data core.DataFragments
		add := func(server bool, wire []byte) {
			dir := reassembly.TCPDirClientToServer
			if server {
				dir = reassembly.TCPDirServerToClient
			}
			for _, b := range wire {
				data = append(data, &core.StreamData{Dir: dir, RawData: []byte{b}})
			}
		}
		add(true, []byte{255, 251, 1, 255, 250, 24, 1, 255, 240})
		add(true, []byte("login:"))
		for _, b := range []byte("aabb") {
			add(false, []byte{b})
			if padded {
				add(true, []byte{b, 0})
			}
		}
		add(false, []byte{'\r', 0, '\n'})
		add(true, []byte("\r\nPassword:"))
		add(false, []byte("synthetic-pass\r\n"))
		var records []*types.Secret
		parseTelnetAuth(&core.ConversationInfo{Data: data}, func(r *types.Secret) { records = append(records, r) })
		if len(records) != 1 || records[0].User != "aabb" || records[0].Password != "synthetic-pass" {
			t.Fatal(padded, records)
		}
	}
}
