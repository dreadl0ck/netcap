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

package stream

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/internal/decoder"
	"github.com/dreadl0ck/netcap/internal/decoder/core"
)

// confusable is traffic that a decoder other than the right one has a reason to
// want.
//
// samples_test.go has one clean sample per decoder, and that set is what a
// decoder author would think to write. It missed the defect that mattered most
// in this area: ranking profinet above dcerpc moved 15 genuine Windows MSRPC
// conversations, on dynamic ports 49667 and 61737, away from dcerpc -- because
// profinet tolerates DCE/RPC version 5 and no sample covered v5 on a port
// neither decoder owns.
//
// These are the cases where two decoders both have a claim. They are the ones
// worth having, and they are not derivable from any single decoder's signature.
type confusable struct {
	name string

	// want is the decoder that should win.
	want string

	// rival is the decoder with the competing claim, named so a failure says
	// which contest was lost.
	rival string

	transport      core.TransportProtocol
	client, server []byte

	// why records what makes this ambiguous.
	why string
}

func confusables() []confusable {
	return []confusable{
		{
			name: "MSRPC on a dynamic port", want: "DCERPC", rival: "PROFINET",
			transport: core.TCP,
			// DCE/RPC v5.0 Bind, connection-oriented: Windows RPC.
			client: append([]byte{0x05, 0x00, 0x0b, 0x03, 0x10, 0x00, 0x00, 0x00, 0x48, 0x00}, make([]byte, 62)...),
			why:    "profinet accepts DCE/RPC v5 to stay usable mid-session; v5 is the connection-oriented form Windows uses",
		},
		{
			name: "PROFINET context manager", want: "PROFINET", rival: "DCERPC",
			transport: core.TCP,
			// DCE/RPC v4, connectionless: what PROFINET CM actually uses.
			client: append([]byte{0x04, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x40, 0x00}, make([]byte, 32)...),
			why:    "dcerpc requires version 5, so only profinet should take v4",
		},
		{
			name: "SMTP submission banner", want: "SMTP", rival: "FTP",
			transport: core.TCP,
			client:    []byte("EHLO relay.example.com\r\n"),
			server:    []byte("220 mx.example.com ESMTP Postfix SMTP\r\n"),
			why:       "both greet with 220; smtp additionally requires SMTP in the banner",
		},
		{
			name: "FTP banner mentioning nothing else", want: "FTP", rival: "SMTP",
			transport: core.TCP,
			client:    []byte("USER anonymous\r\n"),
			server:    []byte("220 ProFTPD 1.3.5 Server ready\r\n"),
			why:       "the 220 both share, without the SMTP token",
		},
		{
			name: "SOCKS5 greeting with a server reply", want: "SOCKS", rival: "DCERPC",
			transport: core.TCP,
			client:    []byte{0x05, 0x01, 0x00},
			server:    []byte{0x05, 0x00},
			why:       "05 01 00 is also a valid DCE/RPC version and packet type",
		},
		{
			name: "RDP connection request", want: "RDP", rival: "S7Comm",
			transport: core.TCP,
			client: tpktFrame(append([]byte{0x0e, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00},
				[]byte("Cookie: mstshash=admin\r\n")...)),
			why: "s7comm accepts any non-DT COTP PDU, and an X.224 connection request is one",
		},
		{
			name: "S7comm read request", want: "S7Comm", rival: "RDP",
			transport: core.TCP,
			client:    s7JobPDU([]byte{0x04, 0x00}),
			why:       "both ride TPKT; only s7comm validates an S7 protocol id",
		},
		{
			name: "ENIP List Services, no CIP payload", want: "PROFINET", rival: "CIP",
			transport: core.TCP,
			// A DCE/RPC v4 header that cip also reads as ENIP command 0x0004.
			client: append([]byte{0x04, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x40, 0x00}, make([]byte, 32)...),
			why:    "cip's header-only commands carry nothing to validate",
		},
		{
			name: "ENIP carrying CIP", want: "CIP", rival: "PROFINET",
			transport: core.TCP,
			client:    enipSendRRData,
			why:       "SendRRData with a declared payload is a real CIP message",
		},
		{
			name: "QUIC Initial", want: "QUICClientHello", rival: "Protobuf",
			transport: core.UDP,
			client:    hexBytes("c000000001" + "0805" + "0102030405060708" + "00" + "4000"),
			why:       "protobuf reads the long-header byte as a valid field tag",
		},
		{
			name: "protobuf over UDP", want: "Protobuf", rival: "QUICClientHello",
			transport: core.UDP,
			// The committed UDP AddressBook corpus, whose first byte is 0x0a:
			// field 1, wire type 2, the opening of almost every protobuf message.
			client: hexBytes("0a420a054a61736f6e10e9071a114a61736f6e406578616d706c652e636f6d" +
				"220c0a08383735363132333410012f220d0a0b31333538383838363636362a0608a18b97fc05"),
			why: "gQUIC accepts any first byte with the connection-id bit set, the version bit " +
				"clear and the top three clear, which 0x0a satisfies",
		},
		{
			name: "DNP3 with a Kerberos-shaped address", want: "DNP3", rival: "Kerberos",
			transport: core.TCP,
			// Byte 4 is the outstation address low byte, and 0x6a is an ASN.1
			// application tag. The header CRC is recomputed for that address,
			// so this is a frame a device could really have sent.
			client: hexBytes("05641ac46a0004005785c1c1030c0128010001000301640000007b5e6400000000005b"),
			why: "kerberos used to read byte 4 as an application tag",
		},
		{
			name: "Modbus with a TACACS-shaped transaction id", want: "Modbus", rival: "TACACS",
			transport: core.TCP,
			client:    []byte{0xC0, 0x01, 0x00, 0x00, 0x00, 0x06, 0x01, 0x03, 0x00, 0x00, 0x00, 0x0A},
			why:       "tacacs used to match on the top nibble of the transaction id alone",
		},
		{
			name: "HTTP mentioning SSH", want: "HTTP", rival: "SSH",
			transport: core.TCP,
			client:    []byte("GET /ssh/SSH-2.0.tar.gz HTTP/1.1\r\nHost: files.example.com\r\n\r\n"),
			server:    []byte("HTTP/1.1 200 OK\r\nContent-Type: application/gzip\r\n\r\nSSH-2.0 archive"),
			why:       "ssh used to match the letters SSH anywhere in the server direction",
		},
		{
			name: "IRC-looking numbers in binary", want: "DNP3", rival: "IRC",
			transport: core.TCP,
			client:    hexBytes("05641ac403000400c9b7c1c1030c0128010001000301640000007b5e6400000000005b"),
			server:    append([]byte{0x00, 0xFF}, []byte("001")...),
			why:       "irc used to match the bare substring 001 in the server direction",
		},
	}
}

// Every confusable case must go to the decoder that has the better claim.
//
// Presented on a port no decoder owns, so the contest is decided by the
// signatures and their specificity rather than by registration.
func TestConfusableTrafficGoesToTheBetterClaim(t *testing.T) {
	matchingEnv(t)

	for _, c := range confusables() {
		t.Run(c.name, func(t *testing.T) {
			sel, ok := SelectDecoder(&SelectionInput{
				Transport:    c.transport,
				ServerPort:   unregisteredPort,
				PortClient:   c.client,
				PortServer:   c.server,
				ScanClient:   c.client,
				ScanServer:   c.server,
				Conversation: &core.ConversationInfo{},
			})

			got := winner(sel, ok)
			if got == c.want {
				return
			}

			if got == c.rival {
				t.Errorf("lost to %s: %s", c.rival, c.why)

				return
			}

			t.Errorf("claimed by %q, want %q (rival was %q): %s", got, c.want, c.rival, c.why)
		})
	}
}

// Reports how each contest is scored, so a close call is visible before it
// becomes a regression.
func TestConfusableSpecificityMargins(t *testing.T) {
	matchingEnv(t)

	score := func(name string, c confusable) (int, bool) {
		for _, port := range SortedDecoderPorts {
			sd := DefaultStreamDecoders[port]
			if sd.GetName() != name || !eligible(sd, c.transport) {
				continue
			}

			if !sd.CanDecodeStream(c.client, c.server) {
				return 0, false
			}

			return sd.MatchSpecificity(c.client, c.server), true
		}

		for _, sd := range UDPStreamDecoders {
			if sd.GetName() == name && eligible(sd, c.transport) && sd.CanDecodeStream(c.client, c.server) {
				return sd.MatchSpecificity(c.client, c.server), true
			}
		}

		return 0, false
	}

	var rows []string

	for _, c := range confusables() {
		wantScore, wantOK := score(c.want, c)
		rivalScore, rivalOK := score(c.rival, c)

		margin := "rival does not match"
		if rivalOK {
			margin = "margin " + itoa(wantScore-rivalScore)
		}

		if !wantOK {
			margin = "WINNER DOES NOT MATCH AT ALL"
		}

		rows = append(rows, strings.Join([]string{
			pad(c.name, 36),
			pad(c.want+" "+itoa(wantScore), 22),
			pad("vs "+c.rival+" "+itoa(rivalScore), 24),
			margin,
		}, ""))
	}

	t.Log("specificity margins in each contest:\n" + strings.Join(rows, "\n"))
}

func pad(s string, n int) string {
	for len(s) < n {
		s += " "
	}

	return s
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}

	neg := n < 0
	if neg {
		n = -n
	}

	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}

	if neg {
		return "-" + string(b)
	}

	return string(b)
}


// Two requests on one keep-alive connection, sent at different times, must not
// share a timestamp.
//
// The reader-hygiene matrix could not see this: its samples put one message in
// each direction, so the two timestamps it observed were the request's and the
// response's, which differed even when every request shared one. Only the
// client direction is populated here, so the two records compared are two
// requests.
//
// Every request used to carry FirstClientPacket and every response
// FirstServerPacket, so an HTTP/1.1 connection serving dozens reported one time
// for all of them.
func TestKeepAliveRequestsDoNotShareATimestamp(t *testing.T) {
	matchingEnv(t)

	var sd *decoder.StreamDecoder

	for _, port := range SortedDecoderPorts {
		if api := DefaultStreamDecoders[port]; api.GetName() == "HTTP" {
			sd, _ = api.(*decoder.StreamDecoder)

			break
		}
	}

	if sd == nil {
		t.Fatal("HTTP decoder not registered")
	}

	writer := &captureWriter{}

	previous := sd.Writer
	sd.Writer = writer

	t.Cleanup(func() { sd.Writer = previous })

	const (
		firstAt  = int64(1_000_000_000)
		secondAt = int64(9_000_000_000)
	)

	client := core.DataFragments{
		hygieneFragment([]byte("GET /one HTTP/1.1\r\nHost: example.com\r\n\r\n"), firstAt, false),
		hygieneFragment([]byte("GET /two HTTP/1.1\r\nHost: example.com\r\n\r\n"), secondAt, false),
	}

	sd.Factory.New(&core.ConversationInfo{
		Data: client, ClientData: client,
		Ident:    "keepalive",
		ClientIP: "192.0.2.1", ServerIP: "192.0.2.2",
		ClientPort: 12345, ServerPort: 80,
		TCPHandshakeComplete: true,
		FirstClientPacket:    time.Unix(0, firstAt),
	}).Decode()

	seen := map[int64]bool{}

	for _, rec := range writer.records {
		if f, ok := field(rec, "Timestamp"); ok && f.Kind() == reflect.Int64 {
			seen[f.Int()] = true
		}
	}

	if len(writer.records) < 2 {
		t.Fatalf("got %d records from two pipelined requests, want 2", len(writer.records))
	}

	if len(seen) < 2 {
		t.Errorf("%d requests on one connection share %d timestamp(s); each should carry the packet it arrived in",
			len(writer.records), len(seen))
	}
}
