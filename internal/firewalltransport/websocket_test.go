package firewalltransport

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func newHandler(t *testing.T, origin string, ws, grpc bool, inspect InspectFunc) *Handler {
	t.Helper()
	u, err := url.Parse(origin)
	if err != nil {
		t.Fatal(err)
	}
	h, err := New(Config{WebSocket: ws, GRPC: grpc, Upstream: u, MessageTimeout: time.Second, MaxConcurrent: 8}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Error(w, "fallback", 418) }), inspect)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func acceptWS(w http.ResponseWriter, r *http.Request) (net.Conn, *bufio.ReadWriter, error) {
	c, rw, err := w.(http.Hijacker).Hijack()
	if err != nil {
		return nil, nil, err
	}
	sum := sha1.Sum([]byte(r.Header.Get("Sec-WebSocket-Key") + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	_, err = fmt.Fprintf(rw, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n", base64.StdEncoding.EncodeToString(sum[:]))
	if err == nil {
		err = rw.Flush()
	}
	return c, rw, err
}

func dialWS(t *testing.T, addr string) (net.Conn, *bufio.Reader) {
	t.Helper()
	c, err := net.Dial("tcp", strings.TrimPrefix(addr, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	_, err = fmt.Fprint(c, "GET /chat?q=1 HTTP/1.1\r\nHost: service.example\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Extensions: permessage-deflate\r\n\r\n")
	if err != nil {
		t.Fatal(err)
	}
	r := bufio.NewReader(c)
	resp, err := http.ReadResponse(r, nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 101 || resp.Header.Get("Sec-WebSocket-Extensions") != "" {
		t.Fatalf("handshake: %+v", resp)
	}
	return c, r
}

func TestWebSocketGateBeforeForwardFragmentedAndDuplex(t *testing.T) {
	received := make(chan string, 8)
	originDone := make(chan struct{})
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer close(originDone)
		if r.Header.Get("Sec-WebSocket-Extensions") != "" {
			t.Error("compression was advertised")
		}
		c, rw, err := acceptWS(w, r)
		if err != nil {
			t.Error(err)
			return
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(3 * time.Second))
		_ = writeWSFrame(c, 1, []byte("welcome"), false)
		for {
			f, err := readWSFrame(rw.Reader, true)
			if err != nil {
				return
			}
			received <- string(f.payload)
			if f.opcode == 9 {
				_ = writeWSFrame(c, 10, f.payload, false)
			}
		}
	}))
	defer origin.Close()
	h := newHandler(t, origin.URL, true, false, func(_ context.Context, e Event) error {
		if e.Protocol != "websocket" || e.Method != "GET" || e.Path != "/chat" || e.RawQuery != "q=1" {
			t.Errorf("bad event: %+v", e)
		}
		if strings.Contains(e.Body, "forbidden") {
			return ErrDenied
		}
		return nil
	})
	proxy := httptest.NewServer(h)
	defer proxy.Close()
	c, r := dialWS(t, proxy.URL)
	f, err := readWSFrame(r, false)
	if err != nil || string(f.payload) != "welcome" {
		t.Fatalf("independent response flow: %q %v", f.payload, err)
	}
	if err := writeWSFrame(c, 1, []byte("hello"), true); err != nil {
		t.Fatal(err)
	}
	// First fragment is withheld; interleaved ping still reaches the peer.
	var fragment bytes.Buffer
	_ = writeWSFrame(&fragment, 1, []byte("for"), true)
	b := fragment.Bytes()
	b[0] &= 127
	_, _ = c.Write(b)
	_ = writeWSFrame(c, 9, []byte("ping"), true)
	f, err = readWSFrame(r, false)
	if err != nil || f.opcode != 10 || string(f.payload) != "ping" {
		t.Fatalf("ping/pong: %+v %v", f, err)
	}
	_ = writeWSFrame(c, 0, []byte("bidden"), true)
	if _, err := r.ReadByte(); err == nil {
		t.Fatal("denied message returned data")
	}
	select {
	case <-originDone:
	case <-time.After(3 * time.Second):
		t.Fatal("origin leaked")
	}
	close(received)
	var got []string
	for s := range received {
		got = append(got, s)
	}
	if strings.Join(got, ",") != "hello,ping" {
		t.Fatalf("denied fragments leaked upstream: %q", got)
	}
}

func TestWebSocketDeniedResponseNeverReleasesFrameHeader(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, _, err := acceptWS(w, r)
		if err != nil {
			t.Error(err)
			return
		}
		defer c.Close()
		_ = writeWSFrame(c, 1, []byte("safe"), false)
		_ = writeWSFrame(c, 1, []byte("secret"), false)
	}))
	defer origin.Close()
	proxy := httptest.NewServer(newHandler(t, origin.URL, true, false, func(_ context.Context, e Event) error {
		if e.Phase == "response" && e.Body == "secret" {
			return ErrDenied
		}
		return nil
	}))
	defer proxy.Close()
	_, r := dialWS(t, proxy.URL)
	f, err := readWSFrame(r, false)
	if err != nil || string(f.payload) != "safe" {
		t.Fatalf("safe response: %q %v", f.payload, err)
	}
	if _, err := r.ReadByte(); err == nil {
		t.Fatal("denied response frame header leaked")
	}
}

func TestWebSocketFramingFailures(t *testing.T) {
	for name, wire := range map[string][]byte{
		"unmasked": {129, 1, 'a'}, "rsv": {193, 128, 0, 0, 0, 0}, "fragment-control": {9, 128, 0, 0, 0, 0}, "nonminimal": {129, 254, 0, 1}, "oversized": {130, 255, 0, 0, 0, 0, 0, 16, 0, 1}, "invalid-opcode": {131, 128, 0, 0, 0, 0},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := readWSFrame(bytes.NewReader(wire), true); err == nil {
				t.Fatal("accepted invalid frame")
			}
		})
	}
	for name, frames := range map[string][]wsFrame{
		"orphan-continuation":  {{final: true, opcode: 0, payload: []byte("x")}},
		"interrupted-fragment": {{final: false, opcode: 1, payload: []byte("x")}, {final: true, opcode: 2, payload: []byte("y")}},
		"invalid-utf8":         {{final: true, opcode: 1, payload: []byte{255}}},
		"invalid-close":        {{final: true, opcode: 8, payload: []byte{0, 1}}},
	} {
		t.Run(name, func(t *testing.T) {
			var wire, got bytes.Buffer
			for _, f := range frames {
				var b bytes.Buffer
				_ = writeWSFrame(&b, f.opcode, f.payload, true)
				raw := b.Bytes()
				if !f.final {
					raw[0] &= 127
				}
				wire.Write(raw)
			}
			err := gateWebSocket(context.Background(), &wire, &got, true, time.Second, func() {}, func([]byte, byte, uint64) error { return nil })
			if !errors.Is(err, ErrFraming) || got.Len() != 0 {
				t.Fatalf("invalid message forwarded: %v %x", err, got.Bytes())
			}
		})
	}
}

func TestWebSocketCloseRelay(t *testing.T) {
	var wire, got bytes.Buffer
	payload := []byte{3, 232, 'b', 'y', 'e'}
	_ = writeWSFrame(&wire, 8, payload, true)
	err := gateWebSocket(context.Background(), &wire, &got, true, time.Second, func() {}, func([]byte, byte, uint64) error { return nil })
	f, readErr := readWSFrame(&got, true)
	if err != io.EOF || readErr != nil || !bytes.Equal(f.payload, payload) {
		t.Fatalf("close: %v %v %+v", err, readErr, f)
	}
}

func TestWebSocketTLSOriginUsesHTTP1AndGracefulClose(t *testing.T) {
	done := make(chan struct{})
	origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer close(done)
		if r.ProtoMajor != 1 {
			t.Error("WebSocket attempted HTTP/2")
		}
		c, rw, err := acceptWS(w, r)
		if err != nil {
			t.Error(err)
			return
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(3 * time.Second))
		f, err := readWSFrame(rw.Reader, true)
		if err != nil {
			t.Error(err)
			return
		}
		if f.opcode != 8 {
			t.Errorf("expected close, got %d", f.opcode)
		}
		_ = writeWSFrame(c, 8, f.payload, false)
	}))
	origin.EnableHTTP2 = true
	origin.StartTLS()
	defer origin.Close()
	u, _ := url.Parse(origin.URL)
	h, err := New(Config{WebSocket: true, Upstream: u, Transport: origin.Client().Transport, MessageTimeout: time.Second, MaxConcurrent: 1}, http.NotFoundHandler(), func(context.Context, Event) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	proxy := httptest.NewServer(h)
	defer proxy.Close()
	c, r := dialWS(t, proxy.URL)
	_ = writeWSFrame(c, 8, []byte{3, 232}, true)
	f, err := readWSFrame(r, false)
	if err != nil || f.opcode != 8 || !bytes.Equal(f.payload, []byte{3, 232}) {
		t.Fatalf("close handshake lost: %+v %v", f, err)
	}
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("upstream close leaked")
	}
}

func TestWebSocketPartialMessageCancellationDrainsBothPumps(t *testing.T) {
	originDone := make(chan struct{})
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer close(originDone)
		c, rw, err := acceptWS(w, r)
		if err != nil {
			t.Error(err)
			return
		}
		defer c.Close()
		data, _ := io.ReadAll(rw.Reader)
		if len(data) != 0 {
			t.Errorf("partial message leaked: %x", data)
		}
	}))
	defer origin.Close()
	h := newHandler(t, origin.URL, true, false, func(context.Context, Event) error { return nil })
	h.cfg.MessageTimeout = 200 * time.Millisecond
	handlerDone := make(chan struct{})
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { defer close(handlerDone); h.ServeHTTP(w, r) }))
	defer proxy.Close()
	c, r := dialWS(t, proxy.URL)
	// Complete header, incomplete masked payload.
	_, _ = c.Write([]byte{129, 133, 0, 0, 0, 0, 'x'})
	if _, err := r.ReadByte(); err == nil {
		t.Fatal("partial message delivered bytes")
	}
	for _, done := range []chan struct{}{handlerDone, originDone} {
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("message pump leaked")
		}
	}
}
