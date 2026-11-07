package firewalltransport

import (
	"bytes"
	"compress/flate"
	"context"
	"crypto/sha1"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func wsCompressed(t *testing.T, text []byte) []byte {
	t.Helper()
	var b bytes.Buffer
	z, e := flate.NewWriter(&b, flate.DefaultCompression)
	if e != nil {
		t.Fatal(e)
	}
	z.Write(text)
	z.Flush()
	wire := append([]byte(nil), b.Bytes()...)
	z.Close()
	return wire[:len(wire)-4]
}

func TestWSDeflateFragmentationBombAndRSV(t *testing.T) {
	for _, tt := range []struct {
		name, text   string
		denied, bomb bool
	}{{"allowed", "hello", false, false}, {"end-denied", "prefix-forbidden", true, false}, {"bomb", "", false, true}} {
		t.Run(tt.name, func(t *testing.T) {
			text := []byte(tt.text)
			if tt.bomb {
				text = bytes.Repeat([]byte("z"), MaxMessageBytes+1)
			}
			compressed := wsCompressed(t, text)
			var wire bytes.Buffer
			writeWSFrame(&wire, 1, compressed[:len(compressed)/2], true)
			first := append([]byte(nil), wire.Bytes()...)
			first[0] = 0x41
			wire.Reset()
			writeWSFrame(&wire, 0, compressed[len(compressed)/2:], true)
			wireBytes := append(first, wire.Bytes()...)
			budget, _ := NewBufferBudget(8 << 20)
			var out bytes.Buffer
			inspected := 0
			err := gateWebSocketExtensions(t.Context(), bytes.NewReader(wireBytes), &out, true, time.Second, func() {}, func(b []byte, op byte, index uint64) error {
				inspected++
				if !bytes.Equal(b, text) {
					t.Fatal("inspection saw compressed/partial bytes")
				}
				if tt.denied {
					return ErrDenied
				}
				return nil
			}, budget, true)
			if tt.bomb {
				if !errors.Is(err, ErrFraming) || inspected != 0 {
					t.Fatalf("bomb %v inspected=%d", err, inspected)
				}
			} else if tt.denied {
				if !errors.Is(err, ErrDenied) {
					t.Fatal(err)
				}
			} else {
				if err != io.EOF {
					t.Fatal(err)
				}
				f, e := readWSFrame(&out, true)
				if e != nil || !bytes.Equal(f.payload, text) {
					t.Fatalf("decoded forwarding %q %v", f.payload, e)
				}
			}
			if (tt.denied || tt.bomb) && out.Len() != 0 {
				t.Fatal("forbidden origin bytes")
			}
			if budget.Used() != 0 {
				t.Fatalf("budget leaked: %d", budget.Used())
			}
			var recovery, recovered bytes.Buffer
			writeWSFrame(&recovery, 1, wsCompressed(t, []byte("safe-recovery")), true)
			recovery.Bytes()[0] |= 64
			err = gateWebSocketExtensions(t.Context(), &recovery, &recovered, true, time.Second, func() {}, func(b []byte, _ byte, _ uint64) error {
				if string(b) != "safe-recovery" {
					t.Fatal("recovery message changed")
				}
				return nil
			}, budget, true)
			if err != io.EOF || recovered.Len() == 0 || budget.Used() != 0 {
				t.Fatalf("capacity did not recover: %v forwarded=%d used=%d", err, recovered.Len(), budget.Used())
			}
		})
	}
	for _, head := range []byte{0xc0, 0xc9, 0xe1} {
		if _, e := readWSFrameExtensions(bytes.NewReader([]byte{head, 0}), false, nil, true); !errors.Is(e, ErrFraming) {
			t.Fatalf("RSV bypass %x %v", head, e)
		}
	}
	if _, e := readWSFrame(bytes.NewReader([]byte{0xc1, 0}), false); !errors.Is(e, ErrFraming) {
		t.Fatal("unnegotiated RSV1 accepted")
	}
}

func TestWSDeflateNegotiationAndCapacity(t *testing.T) {
	for _, v := range []string{"permessage-deflate", "permessage-deflate; server_no_context_takeover", "permessage-deflate; client_no_context_takeover", "permessage-deflate; client_max_window_bits=8", "other"} {
		h := http.Header{"Sec-Websocket-Extensions": []string{v}}
		if wsDeflateResponse(h, true) {
			t.Fatalf("unsafe upstream context negotiation %q", v)
		}
	}
	budget, _ := NewBufferBudget(1024)
	if _, _, e := inflateWS(wsCompressed(t, []byte("safe")), budget); !errors.Is(e, ErrBufferCapacity) || budget.Used() != 0 {
		t.Fatalf("capacity %v used=%d", e, budget.Used())
	}
	for _, wire := range [][]byte{{0xff, 0xff}, {1, 2, 3}, {}} {
		if _, _, e := inflateWS(wire, nil); e == nil {
			t.Fatalf("malformed deflate accepted: %x", wire)
		}
	}
	var history bytes.Buffer
	z, _ := flate.NewWriter(&history, flate.BestCompression)
	payload := bytes.Repeat([]byte("history-only-context-dictionary"), 500)
	z.Write(payload)
	z.Flush()
	offset := history.Len()
	z.Write(payload)
	z.Flush()
	second := append([]byte(nil), history.Bytes()[offset:history.Len()-4]...)
	z.Close()
	if _, _, e := inflateWS(second, nil); e == nil {
		t.Fatal("context-takeover message accepted without history")
	}
	var finished bytes.Buffer
	z, _ = flate.NewWriter(&finished, flate.DefaultCompression)
	z.Write([]byte("safe"))
	z.Close()
	if _, _, e := inflateWS(append(finished.Bytes(), []byte("trailing")...), nil); e == nil {
		t.Fatal("trailing stream bytes accepted")
	}
}

func TestWSDeflateRealPythonClient(t *testing.T) {
	python := os.Getenv("NETCAP_WS_PYTHON")
	if python == "" {
		t.Skip("set NETCAP_WS_PYTHON to Python with websockets==15.0.1")
	}
	received := make(chan string, 8)
	done := make(chan struct{})
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer close(done)
		if r.Header.Get("Sec-WebSocket-Extensions") != wsDeflateExtension {
			t.Error("explicit bounded extension offer missing")
		}
		c, rw, e := w.(http.Hijacker).Hijack()
		if e != nil {
			t.Error(e)
			return
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(5 * time.Second))
		sum := sha1.Sum([]byte(r.Header.Get("Sec-WebSocket-Key") + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
		fmt.Fprintf(rw, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\nSec-WebSocket-Extensions: %s\r\n\r\n", base64.StdEncoding.EncodeToString(sum[:]), wsDeflateExtension)
		rw.Flush()
		for {
			f, e := readWSFrame(rw.Reader, true)
			if e != nil {
				return
			}
			received <- string(f.payload)
			var wire bytes.Buffer
			writeWSFrame(&wire, 1, wsCompressed(t, f.payload), false)
			b := wire.Bytes()
			b[0] |= 64
			c.Write(b)
		}
	}))
	defer origin.Close()
	h := newHandler(t, origin.URL, true, false, func(_ context.Context, e Event) error {
		if strings.Contains(e.Body, "forbidden") {
			return ErrDenied
		}
		return nil
	})
	h.cfg.WebSocketCompression = true
	proxy := httptest.NewServer(h)
	defer proxy.Close()
	script := `import importlib.metadata, sys
assert importlib.metadata.version('websockets') == '15.0.1'
from websockets.sync.client import connect
from websockets.exceptions import ConnectionClosed
with connect(sys.argv[1], compression='deflate', proxy=None, open_timeout=3, close_timeout=1) as ws:
    assert 'client_no_context_takeover' in ws.response.headers['Sec-WebSocket-Extensions']
    for value in ['safe-one', 'safe-two']:
        ws.send(value)
        assert ws.recv(timeout=3) == value
    ws.send(['prefix-for', 'bidden'])
    try:
        ws.recv(timeout=3)
        raise AssertionError('denied message was relayed')
    except ConnectionClosed:
        pass
`
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	b, e := exec.CommandContext(ctx, python, "-c", script, "ws"+strings.TrimPrefix(proxy.URL, "http")).CombinedOutput()
	if e != nil {
		t.Fatalf("real client: %s %v", b, e)
	}
	select {
	case <-done:
	case <-ctx.Done():
		t.Fatal("origin did not close")
	}
	close(received)
	var values []string
	for s := range received {
		values = append(values, s)
	}
	if strings.Join(values, ",") != "safe-one,safe-two" {
		t.Fatalf("origin received %q", values)
	}
	if h.cfg.Budget.Used() != 0 {
		t.Fatalf("live compression budget leak: %d", h.cfg.Budget.Used())
	}
}
