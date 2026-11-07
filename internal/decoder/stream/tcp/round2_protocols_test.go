package tcp

import (
	"encoding/binary"
	"slices"
	"testing"

	"github.com/gogo/protobuf/proto"
	"github.com/gopacket/gopacket/layers"

	"github.com/dreadl0ck/netcap/internal/decoder"
	decoderconfig "github.com/dreadl0ck/netcap/internal/decoder/config"
	"github.com/dreadl0ck/netcap/internal/decoder/stream/ftp"
	"github.com/dreadl0ck/netcap/internal/decoder/stream/irc"
	"github.com/dreadl0ck/netcap/internal/decoder/stream/kerberosaudit"
	"github.com/dreadl0ck/netcap/internal/decoder/stream/pop3"
	"github.com/dreadl0ck/netcap/internal/decoder/stream/rdp"
	"github.com/dreadl0ck/netcap/internal/decoder/stream/smb"
	"github.com/dreadl0ck/netcap/internal/decoder/stream/smtp"
	"github.com/dreadl0ck/netcap/types"
)

// Hand-built protocol messages, not sampled credentials or extracted files.
func TestRound2ConservativeProtocols(t *testing.T) {
	smb1 := make([]byte, 39)
	smb1[3] = 35
	copy(smb1[4:], "\xffSMB")
	smb1[8] = 0x2b // SMB_COM_ECHO
	smb2 := make([]byte, 68)
	smb2[3] = 64
	copy(smb2[4:], "\xfeSMB")
	binary.LittleEndian.PutUint16(smb2[8:10], 64)
	kerberos := append([]byte{0, 0, 0, 66, 0x6a, 64}, make([]byte, 64)...)
	rdpReq := append([]byte{3, 0, 0, 0, 0x0e, 0xe0, 0, 0, 0, 0, 0}, []byte("Cookie: mstshash=fixture\r\n")...)
	binary.BigEndian.PutUint16(rdpReq[2:4], uint16(len(rdpReq)))
	rdpReq[4] = byte(len(rdpReq) - 5)
	for _, tc := range []struct {
		name           string
		port           layers.TCPPort
		decoder        *decoder.StreamDecoder
		client, server string
		observed       func(proto.Message) bool
	}{
		{"FTP", 21, ftp.Decoder, "NOOP\r\n", "220 fixture FTP ready\r\n", func(m proto.Message) bool { return m.(*types.FTP).Command == "NOOP" }},
		{"SMTP", 25, smtp.Decoder, "EHLO fixture.example\r\n", "220 fixture ESMTP ready\r\n", func(m proto.Message) bool { return slices.Contains(m.(*types.SMTP).Commands, "EHLO") }},
		{"POP3", 110, pop3.Decoder, "NOOP\r\n", "+OK fixture POP3 ready\r\n", func(m proto.Message) bool { return slices.Contains(m.(*types.POP3).Commands, "NOOP") }},
		{"IRC", 6667, irc.Decoder, "NICK fixture\r\n", ":irc.example 001 fixture :Welcome\r\n", func(m proto.Message) bool { return m.(*types.IRC).Command == "NICK" }},
		{"SMB1", 445, smb.Decoder, string(smb1), "", func(m proto.Message) bool { return m.(*types.SMB).CommandName == "ECHO" }},
		{"SMB2", 445, smb.Decoder, string(smb2), "", func(m proto.Message) bool { return m.(*types.SMB).CommandName == "NEGOTIATE" }},
		{"Kerberos", 88, kerberosaudit.Decoder, string(kerberos), "", func(m proto.Message) bool { return m.(*types.Kerberos).MessageType == "AS-REQ" }},
		{"RDP", 3389, rdp.Decoder, string(rdpReq), "", func(m proto.Message) bool { return m.(*types.RDP).Username == "fixture" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, mode := range []string{"full", "no-client-SYN", "no-handshake"} {
				t.Run(mode, func(t *testing.T) {
					w := round2Config(t, tc.decoder)
					decoderconfig.Instance.Out = t.TempDir()
					if tc.decoder.PostInit != nil {
						if err := tc.decoder.PostInit(tc.decoder); err != nil {
							t.Fatal(err)
						}
						t.Cleanup(func() {
							if tc.decoder.DeInit != nil {
								_ = tc.decoder.DeInit(tc.decoder)
							}
						})
					}
					r := newRound2Trace(tc.port)
					if mode == "full" {
						r.send(false, 100, "S", "")
					}
					if mode != "no-handshake" {
						r.send(true, 200, "SA", "")
					}
					if tc.server != "" {
						r.send(true, 201, "A", tc.server)
					}
					r.send(false, 101, "A", tc.client)
					r.assembler.FlushAll()
					found := false
					for _, m := range w.records {
						found = found || tc.observed(m)
					}
					if !found {
						t.Fatalf("missing observed %s message (records=%d)", tc.name, len(w.records))
					}
				})
			}
		})
	}
}
