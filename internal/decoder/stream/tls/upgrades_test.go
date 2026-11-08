package tls

import (
	"bytes"
	"testing"

	"github.com/dreadl0ck/netcap/internal/decoder/core"
	"github.com/dreadl0ck/netcap/internal/reassembly"
	"github.com/dreadl0ck/netcap/types"
)

func TestCleartextNegotiationSplitsAndRejections(t *testing.T) {
	h, cw, _ := helloTestWriters(t)
	for _, tc := range []struct{ protocol, request, response, rejection string }{
		{"SMTP", "STARTTLS\r\n", "220 Ready\r\n", "454 Unavailable\r\n"},
		{"POP3", "STLS\r\n", "+OK Begin TLS\r\n", "-ERR Unavailable\r\n"},
		{"IMAP", "A1 STARTTLS\r\n", "A1 OK Begin TLS\r\n", "A1 NO Unavailable\r\n"},
		{"FTP", "AUTH TLS\r\n", "234 Begin TLS\r\n", "534 Unavailable\r\n"},
	} {
		t.Run(tc.protocol, func(t *testing.T) {
			for _, accepted := range []bool{true, false} {
				reply := []byte(tc.response)
				if !accepted {
					reply = []byte(tc.rejection)
				}
				for ci := 0; ci <= len(tc.request); ci++ {
					for si := 0; si <= len(reply); si++ {
						cw.messages = nil
						c := *h.conversation
						c.Data = core.DataFragments{
							fragment([]byte(tc.request[:ci]), false, 1), fragment([]byte(tc.request[ci:]), false, 2),
							fragment(reply[:si], true, 3), fragment(reply[si:], true, 4), fragment(bytes.Clone(upgradeHello()), false, 5),
						}
						ObserveUpgrade(&c, tc.protocol)
						want := 0
						if accepted {
							want = 1
						}
						if len(cw.messages) != want {
							t.Fatalf("accepted=%v splits=%d/%d hellos=%d", accepted, ci, si, len(cw.messages))
						}
					}
				}
			}
		})
	}
}

func upgradeHello() []byte {
	body := append([]byte{3, 3}, make([]byte, 32)...)
	body = append(body, 0, 0, 2, 0xc0, 0x2f, 1, 0, 0, 0)
	return recordWire(22, append([]byte{1, 0, 0, byte(len(body))}, body...))
}

func TestNegotiatedTLSUpgradeRetainsSplitHello(t *testing.T) {
	h, _ := recordTestSetup(t)
	old, count := ClientHelloDecoder.Writer, ClientHelloDecoder.NumRecordsWritten
	t.Cleanup(func() { ClientHelloDecoder.Writer, ClientHelloDecoder.NumRecordsWritten = old, count })
	for _, tc := range []struct{ protocol, request, response string }{{"SMTP", "STARTTLS\r\n", "220 Ready\r\n"}, {"IMAP", "A1 STARTTLS\r\n", "A1 OK Begin TLS\r\n"}, {"POP3", "STLS\r\n", "+OK Begin TLS\r\n"}, {"FTP", "AUTH TLS\r\n", "234 Begin TLS\r\n"}} {
		for split := 1; split < len(upgradeHello()); split++ {
			w := &helloWriter{}
			ClientHelloDecoder.Writer = w
			c := *h.conversation
			c.Data = core.DataFragments{&core.StreamData{RawData: []byte(tc.request)}, &core.StreamData{RawData: []byte(tc.response), Dir: reassembly.TCPDirServerToClient}, &core.StreamData{RawData: upgradeHello()[:split]}, &core.StreamData{RawData: upgradeHello()[split:]}}
			ObserveUpgrade(&c, tc.protocol)
			if len(w.messages) != 1 || w.messages[0].(*types.TLSClientHello).SrcIP != "192.0.2.1" {
				t.Fatalf("%s split %d: %v", tc.protocol, split, w.messages)
			}
		}
	}
}

func TestTLSUpgradeRequiresAcknowledgedControlExchange(t *testing.T) {
	for _, fragments := range []core.DataFragments{
		{&core.StreamData{RawData: []byte("STARTTLS\r\n")}, &core.StreamData{RawData: []byte("454 Not available\r\n"), Dir: reassembly.TCPDirServerToClient}},
		{&core.StreamData{RawData: []byte("DATA\r\nSTARTTLS\r\n")}, &core.StreamData{RawData: []byte("220 text\r\n"), Dir: reassembly.TCPDirServerToClient}},
		{&core.StreamData{RawData: []byte("STARTTLS\r\n")}, &core.StreamData{RawData: []byte("220 Ready\r\n"), SkippedBytes: 1, Dir: reassembly.TCPDirServerToClient}},
	} {
		if _, ok := cleartextUpgrade(fragments, ""); ok {
			t.Fatal("unconfirmed upgrade accepted")
		}
	}
}

func TestCleartextUpgradeUsesPrimaryProtocol(t *testing.T) {
	for _, tc := range []struct{ primary, request, response string }{
		{"SMTP", "STARTTLS\r\n", "220 Ready\r\n"},
		{"POP3", "STLS\r\n", "+OK Begin TLS\r\n"},
		{"IMAP", "A1 STARTTLS\r\n", "A1 OK Begin TLS\r\n"},
		{"FTP", "AUTH TLS\r\n", "234 Begin TLS\r\n"},
	} {
		for _, primary := range []string{"SMTP", "POP3", "IMAP", "FTP"} {
			fragments := core.DataFragments{fragment([]byte(tc.request), false, 1), fragment([]byte(tc.response), true, 2)}
			if _, ok := cleartextUpgrade(fragments, primary); ok != (primary == tc.primary) {
				t.Fatalf("%s command accepted=%v for %s", tc.primary, ok, primary)
			}
		}
	}
}

func TestReverseSOCKSTunnelHandsOffTLS(t *testing.T) {
	h, _ := recordTestSetup(t)
	old, count := ClientHelloDecoder.Writer, ClientHelloDecoder.NumRecordsWritten
	t.Cleanup(func() { ClientHelloDecoder.Writer, ClientHelloDecoder.NumRecordsWritten = old, count })
	w := &helloWriter{}
	ClientHelloDecoder.Writer = w
	c := *h.conversation
	c.Data = core.DataFragments{&core.StreamData{RawData: []byte{5, 1, 0, 1, 192, 0, 2, 10, 1, 187}, Dir: reassembly.TCPDirServerToClient}, &core.StreamData{RawData: []byte{5, 0, 0, 1, 192, 0, 2, 10, 1, 187}}, &core.StreamData{RawData: upgradeHello(), Dir: reassembly.TCPDirServerToClient}}
	ObserveUpgrade(&c, "")
	if len(w.messages) != 1 || w.messages[0].(*types.TLSClientHello).SrcIP != "192.0.2.2" {
		t.Fatal(w.messages)
	}
	w.messages = nil
	ObserveUpgrade(&c, "HTTP")
	if len(w.messages) != 0 {
		t.Fatal("HTTP body searched for TLS")
	}
}

func TestImplicitTLSHelloIsNotHiddenByPlainSMTPGreeting(t *testing.T) {
	h, _ := recordTestSetup(t)
	old, count := ClientHelloDecoder.Writer, ClientHelloDecoder.NumRecordsWritten
	t.Cleanup(func() { ClientHelloDecoder.Writer, ClientHelloDecoder.NumRecordsWritten = old, count })
	w := &helloWriter{}
	ClientHelloDecoder.Writer = w
	c := *h.conversation
	c.Data = core.DataFragments{&core.StreamData{RawData: upgradeHello()}, &core.StreamData{RawData: []byte("220 plaintext SMTP\r\n"), Dir: reassembly.TCPDirServerToClient}}
	ObserveUpgrade(&c, "SMTP")
	if len(w.messages) != 1 {
		t.Fatal(w.messages)
	}
}

func TestSOCKSControlMessagesAcrossTCPBoundaries(t *testing.T) {
	request, reply := []byte{5, 1, 0, 1, 192, 0, 2, 10, 1, 187}, []byte{5, 0, 0, 1, 192, 0, 2, 10, 1, 187}
	for a := 1; a < len(request); a++ {
		for b := 1; b < len(reply); b++ {
			fragments := core.DataFragments{&core.StreamData{RawData: request[:a]}, &core.StreamData{RawData: request[a:]}, &core.StreamData{RawData: reply[:b], Dir: reassembly.TCPDirServerToClient}, &core.StreamData{RawData: reply[b:], Dir: reassembly.TCPDirServerToClient}}
			if bounds, ok := socksUpgrade(fragments); !ok || bounds != [2]int{10, 10} {
				t.Fatalf("splits %d/%d: %v %v", a, b, bounds, ok)
			}
		}
	}
}
