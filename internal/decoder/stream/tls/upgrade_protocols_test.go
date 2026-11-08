package tls

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/dreadl0ck/netcap/internal/decoder/core"
	"github.com/dreadl0ck/netcap/types"
)

type upgradeCase struct {
	name           string
	client, server []byte
	parse          upgradeParser
}

func upgradeCases() []upgradeCase {
	ldapReq := append([]byte{0x30, 29, 2, 1, 1, 0x77, 24, 0x80, 22}, []byte(ldapStartTLSOID)...)
	ldapResp := []byte{0x30, 12, 2, 1, 1, 0x78, 7, 0x0a, 1, 0, 4, 0, 4, 0}
	greeting := append([]byte{10, '8', 0}, make([]byte, 13)...)
	greeting = append(greeting, 0, 0x0a)
	greeting = append(greeting, make([]byte, 16)...)
	mysqlServer := append([]byte{byte(len(greeting)), 0, 0, 0}, greeting...)
	mysqlClient := append([]byte{32, 0, 0, 1, 0, 0x0a, 0, 0}, make([]byte, 28)...)
	rdp := func(response bool) []byte {
		b := []byte{3, 0, 0, 19, 14, 0xe0, 0, 0, 0, 0, 0, 1, 0, 8, 0, 3, 0, 0, 0}
		if response {
			b[5], b[11], b[15] = 0xd0, 2, 1
		}
		return b
	}
	return []upgradeCase{
		{"HTTP", []byte("CONNECT example.test:443 HTTP/1.1\r\nHost: example.test\r\n\r\n"), []byte("HTTP/1.1 200 Connection established\r\nX-Proxy: fixture\r\n\r\n"), connectBounds},
		{"LDAP", ldapReq, ldapResp, ldapBounds},
		{"PostgreSQL", []byte{0, 0, 0, 8, 4, 210, 22, 47}, []byte{'S'}, postgresBounds},
		{"MySQL", mysqlClient, mysqlServer, mysqlBounds},
		{"XMPP", []byte("<stream:stream xmlns:stream='http://etherx.jabber.org/streams'><starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>"), []byte("<stream:stream xmlns:stream='http://etherx.jabber.org/streams'><stream:features><starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/></stream:features><proceed xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>"), xmppBounds},
		{"IRC", []byte("CAP LS\r\nSTARTTLS\r\n"), []byte(":server CAP * LS :tls\r\n:server 670 * :STARTTLS successful\r\n"), ircBounds},
		{"RDP", rdp(false), rdp(true), rdpBounds},
		{"SOCKS", []byte{5, 1, 0, 5, 1, 0, 1, 192, 0, 2, 1, 1, 187}, []byte{5, 0, 5, 0, 0, 1, 192, 0, 2, 1, 1, 187}, socksBounds},
	}
}

func TestUpgradeExactBoundaries(t *testing.T) {
	h, cw, sw := helloTestWriters(t)
	for _, tc := range upgradeCases() {
		t.Run(tc.name, func(t *testing.T) {
			client := append(bytes.Clone(tc.client), upgradeHello()...)
			server := append(bytes.Clone(tc.server), recordHello(2)...)
			want := [2]int{len(tc.client), len(tc.server)}
			if got, ok := tc.parse(client, server); !ok || got != want {
				t.Fatalf("bounds %v %v want %v", got, ok, want)
			}
			for _, reverse := range []bool{false, true} {
				for split := 0; split <= len(client); split++ {
					cw.messages, sw.messages = nil, nil
					c := *h.conversation
					// A complete opposing direction may be delivered between split request bytes.
					c.Data = core.DataFragments{fragment(client[:split], reverse, 1), fragment(server, !reverse, 2), fragment(client[split:], reverse, 3)}
					ObserveUpgrade(&c, tc.name)
					if len(cw.messages) != 1 || len(sw.messages) != 1 {
						t.Fatalf("reverse=%v client split=%d: %v %v", reverse, split, cw.messages, sw.messages)
					}
					if cw.messages[0].(*types.TLSClientHello).SrcIP != map[bool]string{false: c.ClientIP, true: c.ServerIP}[reverse] {
						t.Fatal("wrong upgraded role")
					}
					if sw.messages[0].(*types.TLSServerHello).SrcIP != map[bool]string{false: c.ServerIP, true: c.ClientIP}[reverse] {
						t.Fatal("wrong upgraded server role")
					}
				}
				for split := 0; split <= len(server); split++ {
					cw.messages, sw.messages = nil, nil
					c := *h.conversation
					c.Data = core.DataFragments{fragment(server[:split], !reverse, 1), fragment(client, reverse, 2), fragment(server[split:], !reverse, 3)}
					ObserveUpgrade(&c, tc.name)
					if len(cw.messages) != 1 || len(sw.messages) != 1 {
						t.Fatalf("reverse=%v server split=%d: %v %v", reverse, split, cw.messages, sw.messages)
					}
				}
			}
			for cut := range len(tc.client) {
				cw.messages = nil
				c := *h.conversation
				gap := fragment(client[cut:], false, 3)
				gap.SkippedBytes = 1
				c.Data = core.DataFragments{fragment(client[:cut], false, 1), fragment(server, true, 2), gap}
				ObserveUpgrade(&c, tc.name)
				if len(cw.messages) != 0 {
					t.Fatalf("negotiation bridged gap at %d", cut)
				}
			}
			for _, gapAt := range []int{len(tc.client), len(tc.client) + 10} {
				cw.messages = nil
				c := *h.conversation
				gap := fragment(nil, false, 3)
				gap.SkippedBytes = 1
				c.Data = core.DataFragments{fragment(client[:gapAt], false, 1), fragment(server, true, 2), gap, fragment(client[gapAt:], false, 4)}
				ObserveUpgrade(&c, tc.name)
				if len(cw.messages) != 0 {
					t.Fatal("TLS bridged zero-length gap at handoff")
				}
			}
			// Bytes at an unnegotiated offset, even a valid hello, cannot become TLS.
			cw.messages = nil
			c := *h.conversation
			c.Data = core.DataFragments{fragment(append(bytes.Clone(tc.client), append([]byte("junk"), upgradeHello()...)...), false, 1), fragment(server, true, 2)}
			ObserveUpgrade(&c, tc.name)
			if len(cw.messages) != 0 {
				t.Fatal("scanned beyond negotiated boundary")
			}
		})
	}
}

func TestUpgradeRejectedAndMalformed(t *testing.T) {
	h, cw, sw := helloTestWriters(t)
	for _, tc := range upgradeCases() {
		t.Run(tc.name, func(t *testing.T) {
			for cut := 0; cut < len(tc.client); cut++ {
				if _, ok := tc.parse(tc.client[:cut], tc.server); ok {
					t.Fatalf("truncated request %d accepted", cut)
				}
			}
			for cut := 0; cut < len(tc.server); cut++ {
				if _, ok := tc.parse(tc.client, tc.server[:cut]); ok {
					t.Fatalf("truncated response %d accepted", cut)
				}
			}
			c, s := bytes.Clone(tc.client), bytes.Clone(tc.server)
			switch tc.name {
			case "HTTP":
				s = []byte("HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
			case "LDAP":
				s[9] = 53
			case "PostgreSQL":
				s[0] = 'N'
			case "MySQL":
				c[5] = 2
			case "XMPP":
				s = bytes.ReplaceAll(s, []byte("proceed"), []byte("failure"))
			case "IRC":
				s = bytes.ReplaceAll(s, []byte("670"), []byte("691"))
			case "RDP":
				s[11] = 3
			case "SOCKS":
				s[3] = 5
			}
			if _, ok := tc.parse(append(c, upgradeHello()...), append(s, recordHello(2)...)); ok {
				t.Fatal("rejected negotiation accepted")
			}
			cw.messages, sw.messages = nil, nil
			conversation := *h.conversation
			conversation.Data = core.DataFragments{fragment(append(bytes.Clone(c), upgradeHello()...), false, 1), fragment(append(bytes.Clone(s), recordHello(2)...), true, 2)}
			ObserveUpgrade(&conversation, tc.name)
			if len(cw.messages) != 0 || len(sw.messages) != 0 {
				t.Fatal("rejected upgrade emitted TLS metadata")
			}
		})
	}
	for _, c := range []string{"GET / HTTP/1.1\r\nContent-Length: 23\r\n\r\nCONNECT host:443 HTTP/1.1", "CONNECTED host:443 HTTP/1.1\r\n\r\n"} {
		if _, ok := connectBounds([]byte(c), []byte("HTTP/1.1 200 OK\r\n\r\n")); ok {
			t.Fatal("not a CONNECT request")
		}
	}
	if _, ok := xmppBounds([]byte("junk<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>"), []byte("<proceed xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>")); ok {
		t.Fatal("XMPP searched arbitrary bytes")
	}
	if _, ok := ldapBounds(upgradeCases()[1].client, []byte{0x30, 12, 2, 1, 2, 0x78, 7, 10, 1, 0, 4, 0, 4, 0}); ok {
		t.Fatal("LDAP message ID not correlated")
	}
}

func TestIRCRequiresSTARTTLSCommand(t *testing.T) {
	response := []byte(":server 670 * :STARTTLS successful\r\n")
	for _, request := range []string{"", "NICK user\r\n", "CAP LS\r\nNICK user\r\n", "STARTTLS ignored\r\n"} {
		if _, ok := ircBounds([]byte(request), response); ok {
			t.Fatalf("unsolicited IRC acceptance for %q", request)
		}
	}
}

func TestUpgradeLossBoundaries(t *testing.T) {
	h, cw, _ := helloTestWriters(t)
	cases := upgradeCases()
	for _, tc := range []struct{ name, request, response string }{
		{"SMTP", "STARTTLS\r\n", "220 Ready\r\n"},
		{"POP3", "STLS\r\n", "+OK Begin TLS\r\n"},
		{"IMAP", "A1 STARTTLS\r\n", "A1 OK Begin TLS\r\n"},
		{"FTP", "AUTH TLS\r\n", "234 Begin TLS\r\n"},
	} {
		cases = append(cases, upgradeCase{name: tc.name, client: []byte(tc.request), server: []byte(tc.response)})
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, serverLoss := range []bool{false, true} {
				for _, discarded := range []bool{false, true} {
					// Exercise a hole inside negotiation, at the handoff, and inside the hello.
					preamble := tc.client
					if serverLoss {
						preamble = tc.server
					}
					for _, cut := range []int{1, len(preamble), len(preamble) + 10} {
						cw.messages = nil
						c := *h.conversation
						payload := append(bytes.Clone(preamble), upgradeHello()...)
						marker := fragment(nil, serverLoss, 3)
						if discarded {
							marker.DiscardedBytes, marker.DiscardReason = 1, "retention-budget"
						} else {
							marker.SkippedBytes = 1
						}
						other := tc.server
						if serverLoss {
							other = tc.client
						}
						c.Data = core.DataFragments{fragment(payload[:cut], serverLoss, 1), marker, fragment(payload[cut:], serverLoss, 4), fragment(other, !serverLoss, 5)}
						ObserveUpgrade(&c, tc.name)
						if len(cw.messages) != 0 {
							t.Fatalf("server=%v discarded=%v cut=%d: crossed loss boundary", serverLoss, discarded, cut)
						}
					}
				}
			}
		})
	}
}

func TestUpgradePrefixBudget(t *testing.T) {
	for _, tc := range upgradeCases() {
		t.Run(tc.name, func(t *testing.T) {
			// Negotiation beyond the retained prefix must not be searched for.
			padding := bytes.Repeat([]byte{' '}, maxUpgradeBytes)
			data := upgradePrefixes(core.DataFragments{
				fragment(padding, false, 1), fragment(tc.client, false, 2), fragment(tc.server, true, 3),
			})
			if len(data[0]) != maxUpgradeBytes || len(data[1]) > maxUpgradeBytes {
				t.Fatal("upgrade prefix exceeded budget")
			}
			if _, ok := tryUpgrade(data, tc.parse); ok {
				t.Fatal("negotiation discovered beyond budget")
			}
		})
	}
}

func TestHTTPConnectAuthenticationRetryAndInformational(t *testing.T) {
	c := upgradeCases()[0].client
	s := []byte("HTTP/1.1 407 Auth required\r\nContent-Length: 4\r\n\r\nbodyHTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 201 Established\r\nContent-Length: 999\r\n\r\n")
	if got, ok := connectBounds(append(bytes.Clone(c), c...), append(bytes.Clone(s), upgradeHello()...)); !ok || got != [2]int{2 * len(c), len(s)} {
		t.Fatalf("CONNECT status/header boundary: %v %v", got, ok)
	}
}

func FuzzNegotiatedUpgrade(f *testing.F) {
	for _, tc := range upgradeCases() {
		f.Add(tc.client, tc.server)
	}
	f.Fuzz(func(t *testing.T, c, s []byte) {
		if len(c) > maxUpgradeBytes || len(s) > maxUpgradeBytes {
			return
		}
		for _, tc := range upgradeCases() {
			if bounds, ok := tc.parse(c, s); ok && (bounds[0] <= 0 || bounds[0] > len(c) || bounds[1] <= 0 || bounds[1] > len(s)) {
				t.Fatalf("invalid %s bounds %v", tc.name, bounds)
			}
		}
	})
}

func TestPostgresGSSRefusalThenSSL(t *testing.T) {
	c := []byte{0, 0, 0, 8, 4, 210, 22, 48, 0, 0, 0, 8, 4, 210, 22, 47}
	if b, ok := postgresBounds(c, []byte("NS")); !ok || b != [2]int{16, 2} {
		t.Fatal(b, ok)
	}
	binary.BigEndian.PutUint32(c[:4], 9)
	if _, ok := postgresBounds(c, []byte("NS")); ok {
		t.Fatal("malformed startup length")
	}
}
