package secret

import (
	"encoding/base64"
	"github.com/dreadl0ck/netcap/internal/decoder/core"
	"github.com/dreadl0ck/netcap/internal/reassembly"
	"github.com/dreadl0ck/netcap/types"
	"testing"
)

func TestPOPAndIMAPAuthAcrossFragmentBoundaries(t *testing.T) {
	b64 := func(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }
	for _, tc := range []struct{ protocol, wire, user, password string }{
		{"POP3", "AUTH PLAIN " + b64("\x00analyst\x00fixture") + "\r\n", "analyst", "fixture"},
		{"POP3", "AUTH LOGIN\r\n" + b64("analyst") + "\r\n" + b64("fixture") + "\r\n", "analyst", "fixture"},
		{"IMAP", "A1 LOGIN \"Test Analyst\" \"a\\\"b\"\r\n", "Test Analyst", "a\"b"},
		{"IMAP", "A1 AUTHENTICATE PLAIN\r\n" + b64("\x00analyst\x00fixture") + "\r\n", "analyst", "fixture"},
	} {
		for split := 1; split < len(tc.wire); split++ {
			port := int32(110)
			greeting := "+OK POP3\r\n"
			if tc.protocol == "IMAP" {
				port = 143
				greeting = "* OK IMAP\r\n"
			}
			c := &core.ConversationInfo{ServerPort: port, Data: core.DataFragments{&core.StreamData{Dir: reassembly.TCPDirServerToClient, RawData: []byte(greeting)}, &core.StreamData{RawData: []byte(tc.wire[:split])}, &core.StreamData{RawData: []byte(tc.wire[split:])}}}
			var records []*types.Secret
			parseMailAuth(c, tc.protocol, func(r *types.Secret) { records = append(records, r) })
			if len(records) != 1 || records[0].User != tc.user || records[0].Password != tc.password {
				t.Fatalf("%s split %d: %v", tc.protocol, split, records)
			}
		}
	}
}

func TestMailAuthStopsAtTLSAndAtGaps(t *testing.T) {
	for _, gap := range []int{0, 10} {
		c := &core.ConversationInfo{ServerPort: 143, Data: core.DataFragments{&core.StreamData{RawData: []byte("A1 STARTTLS\r\n")}, &core.StreamData{RawData: []byte("A1 OK TLS\r\n"), Dir: reassembly.TCPDirServerToClient}, &core.StreamData{RawData: []byte("A2 LOGIN fake forged\r\n"), SkippedBytes: gap}}}
		parseMailAuth(c, "IMAP", func(*types.Secret) { t.Fatal("TLS ciphertext harvested as login") })
	}
}
