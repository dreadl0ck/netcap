package gateway

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/internal/policy"
)

func TestFTPTransferLimitAndPassiveCancellation(t *testing.T) {
	for _, mode := range []string{"oversized", "cancel-accept", "cancel-read", "wrong-peer"} {
		t.Run(mode, func(t *testing.T) {
			o := fixtureOrigin(t, func(c net.Conn, o *wireOrigin) {
				c.Write([]byte("220 owned\r\n"))
				r := bufio.NewReader(c)
				for {
					b, e := boundedLine(r, 4096)
					if e != nil {
						return
					}
					o.record(b)
					if bytes.Equal(b, []byte("EPSV\r\n")) {
						c.Write([]byte("229 passive (|||65534|)\r\n"))
					} else {
						c.Write([]byte("200 OK\r\n"))
					}
				}
			})
			c, cancel, _ := startTCPGateway(t, Config{Protocol: "ftp", Upstream: o.listener.Addr().String(), MaxMessageBytes: 512}, allowAll())
			r := bufio.NewReader(c)
			r.ReadString('\n')
			fmt.Fprint(c, "EPSV\r\n")
			reply, _ := r.ReadString('\n')
			port, e := ftpPassivePort([]byte(reply))
			if e != nil {
				t.Fatal(e)
			}
			var d *net.TCPConn
			if mode != "cancel-accept" {
				var local *net.TCPAddr
				if mode == "wrong-peer" {
					local = &net.TCPAddr{IP: net.ParseIP("127.0.0.2")}
				}
				d, e = net.DialTCP("tcp", local, &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: port})
				if e != nil {
					if mode == "wrong-peer" && errors.Is(e, syscall.EADDRNOTAVAIL) {
						t.Skip("alternate loopback address unavailable; run this subtest in Linux fixture")
					}
					t.Fatal(e)
				}
				defer d.Close()
			}
			fmt.Fprint(c, "STOR forbidden.txt\r\n")
			if reply, e = r.ReadString('\n'); e != nil || !strings.HasPrefix(reply, "150 ") {
				t.Fatalf("preliminary %q %v", reply, e)
			}
			if mode == "oversized" {
				d.Write(bytes.Repeat([]byte("x"), 513))
				d.CloseWrite()
			} else if mode != "wrong-peer" {
				cancel()
			}
			c.SetReadDeadline(time.Now().Add(time.Second))
			if _, e = r.ReadByte(); e == nil {
				t.Fatal("invalid transfer remained open")
			} else if ne, ok := e.(net.Error); ok && ne.Timeout() {
				t.Fatal("transfer did not cancel")
			}
			o.wait(t)
			if bytes.Contains(o.snapshot(), []byte("STOR")) {
				t.Fatal("invalid transfer caused origin operation")
			}
			probe, e := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), time.Second)
			if e == nil {
				probe.Close()
				t.Fatal("passive listener leaked")
			}
		})
	}
}

func TestFTPRejectsPartialTLSConfiguration(t *testing.T) {
	for _, c := range []Config{
		{TLSCert: "not-loaded", TLSKey: "not-loaded"},
		{UpstreamTLS: true, UpstreamServerName: "owned.test"},
	} {
		c.Protocol, c.Upstream = "ftp", "127.0.0.1:2121"
		if _, err := New(c, allowAll()); err == nil || !strings.Contains(err.Error(), "plaintext") {
			t.Fatalf("partial FTP TLS accepted: %v", err)
		}
	}
}

func TestFTPCredentialsOpaqueAndUnsupportedNeverForwarded(t *testing.T) {
	o := fixtureOrigin(t, func(c net.Conn, o *wireOrigin) {
		c.Write([]byte("220 owned\r\n"))
		r := bufio.NewReader(c)
		for {
			b, e := boundedLine(r, 4096)
			if e != nil {
				return
			}
			o.record(b)
			c.Write([]byte("230 OK\r\n"))
		}
	})
	events := make(chan policy.Event, 8)
	c, _, _ := startTCPGateway(t, Config{Protocol: "ftp", Upstream: o.listener.Addr().String()}, evaluateFunc(func(e policy.Event) (policy.Decision, error) {
		events <- e
		return policy.Decision{Verdict: "allow"}, nil
	}))
	r := bufio.NewReader(c)
	r.ReadString('\n')
	for _, line := range []string{"USER opaque-user\r\n", "PASS opaque-secret\r\n", "SITE DELE forbidden\r\n", "PORT 127,0,0,2,10,10\r\n", "PASV\r\n", "AUTH TLS\r\n"} {
		c.Write([]byte(line))
		if _, e := r.ReadString('\n'); e != nil {
			t.Fatal(e)
		}
	}
	c.Close()
	o.wait(t)
	for i := 0; i < 2; i++ {
		e := <-events
		if s := fmt.Sprint(e); strings.Contains(s, "opaque-user") || strings.Contains(s, "opaque-secret") {
			t.Fatal("credential exposed")
		}
	}
	w := o.snapshot()
	if bytes.Contains(w, []byte("SITE")) || bytes.Contains(w, []byte("PORT")) || bytes.Contains(w, []byte("PASV")) || bytes.Contains(w, []byte("AUTH")) {
		t.Fatalf("unsupported mode escaped: %q", w)
	}
}

func TestSMBPartialAndOversizedFramesCancelWithoutDial(t *testing.T) {
	for _, wire := range [][]byte{{0, 0, 0, 100, 0xfe, 'S'}, {0, 0xff, 0xff, 0xff}} {
		t.Run(fmt.Sprintf("%x", wire), func(t *testing.T) {
			o := fixtureOrigin(t, func(c net.Conn, o *wireOrigin) { o.record([]byte("connected")) })
			c, cancel, _ := startTCPGateway(t, Config{Protocol: "smb", Upstream: o.listener.Addr().String(), MaxMessageBytes: 512}, allowAll())
			c.Write(wire)
			cancel()
			c.SetReadDeadline(time.Now().Add(time.Second))
			_, e := io.ReadAll(c)
			if ne, ok := e.(net.Error); ok && ne.Timeout() {
				t.Fatal("partial frame blocked cancellation")
			}
			o.listener.Close()
			o.wait(t)
			if len(o.snapshot()) != 0 {
				t.Fatal("partial frame dialed")
			}
		})
	}
}
