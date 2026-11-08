package waf

import (
	"bufio"
	"bytes"
	"compress/flate"
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/internal/firewallstate"
	"github.com/dreadl0ck/netcap/internal/policy"
)

func rpcWire(body string) []byte {
	b := make([]byte, 5+len(body))
	binary.BigEndian.PutUint32(b[1:], uint32(len(body)))
	copy(b[5:], body)
	return b
}

type hookStore struct {
	count    atomic.Int64
	revision string
	t        *testing.T
}

func (s *hookStore) Count(_ context.Context, key firewallstate.Key, _ firewallstate.Window, _ time.Time) (firewallstate.CountResult, error) {
	if key.Revision != s.revision {
		s.t.Errorf("guard received unpinned revision %s", key.Revision)
	}
	return firewallstate.CountResult{Count: s.count.Add(1)}, nil
}

func TestMessageEvaluatorCoversGRPCHeadersMessagesTrailersAndGuardCounts(t *testing.T) {
	origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		if r.Trailer.Get("X-Request-Finish") != "done" {
			t.Errorf("request trailer lost: %v", r.Trailer)
		}
		w.Header().Set("Content-Type", "application/grpc")
		w.Header().Set("Trailer", "Grpc-Status")
		_, _ = w.Write(rpcWire("one"))
		_, _ = w.Write(rpcWire("two"))
		w.Header().Set("Grpc-Status", "0")
	}))
	origin.EnableHTTP2 = true
	origin.StartTLS()
	defer origin.Close()
	p := compiled(t, "enforce", "request", "")
	f := firewall(t, config(origin.URL), p)
	f.transport.TLSClientConfig = origin.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	store := &hookStore{revision: p.Revision(), t: t}
	guard, err := firewallstate.NewGuardWithStore(firewallstate.GuardConfig{ID: "shared", Limit: 8, Window: time.Minute, GroupBy: "ClientIP"}, store)
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	seen := map[string]int{}
	if err := f.SetEvaluator(func(ctx context.Context, snapshot *policy.Compiled, e policy.Event) (policy.Decision, error) {
		if e.Body != "" {
			t.Errorf("body-independent message copied native Body: %d", len(e.Body))
		}
		if snapshot != p || e.Protocol != "grpc" {
			t.Errorf("message hook lost snapshot/protocol: %p %s", snapshot, e.Protocol)
		}
		mu.Lock()
		seen[e.Phase+":"+e.Attributes["inspection.kind"]]++
		mu.Unlock()
		return guard.Evaluate(ctx, snapshot, e)
	}); err != nil {
		t.Fatal(err)
	}
	h, err := f.MessageHandler(false, true)
	if err != nil {
		t.Fatal(err)
	}
	proxy := httptest.NewUnstartedServer(h)
	proxy.EnableHTTP2 = true
	proxy.StartTLS()
	defer proxy.Close()
	wire := append(rpcWire("first"), rpcWire("second")...)
	req, _ := http.NewRequest("POST", proxy.URL+"/service/chat", bytes.NewReader(wire))
	req.Header.Set("Content-Type", "application/grpc")
	req.Trailer = http.Header{"X-Request-Finish": []string{"done"}}
	resp, err := proxy.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_, err = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	for kind, want := range map[string]int{"request:headers": 1, "request:message": 2, "request:trailers": 1, "response:headers": 1, "response:message": 2, "response:trailers": 1} {
		if seen[kind] != want {
			t.Errorf("hook %s count=%d want=%d", kind, seen[kind], want)
		}
	}
	// Guard admission counts the initial request, while the hook sees every event.
	if store.count.Load() != 1 {
		t.Fatalf("shared guard event semantics changed: %d", store.count.Load())
	}
}

func TestMessageHandlerNativePolicyBeforeGRPCForwarding(t *testing.T) {
	for _, phase := range []string{"request", "response"} {
		t.Run(phase, func(t *testing.T) {
			var received atomic.Int64
			origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				data, _ := io.ReadAll(r.Body)
				received.Add(int64(len(data)))
				w.Header().Set("Content-Type", "application/grpc")
				_, _ = w.Write(rpcWire("safe"))
				_, _ = w.Write(rpcWire("secret"))
			}))
			origin.EnableHTTP2 = true
			origin.StartTLS()
			defer origin.Close()
			c := config(origin.URL)
			f := firewall(t, c, compiled(t, "enforce", phase, `Protocol == "grpc" && Attributes["inspection.kind"] == "message" && Body contains "secret"`))
			f.transport.TLSClientConfig = origin.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
			h, err := f.MessageHandler(false, true)
			if err != nil {
				t.Fatal(err)
			}
			proxy := httptest.NewUnstartedServer(h)
			proxy.EnableHTTP2 = true
			proxy.StartTLS()
			defer proxy.Close()
			request := "safe"
			if phase == "request" {
				request = "secret"
			}
			req, _ := http.NewRequest("POST", proxy.URL+"/service/method", bytes.NewReader(rpcWire(request)))
			req.Header.Set("Content-Type", "application/grpc")
			resp, err := proxy.Client().Do(req)
			var data []byte
			if err == nil {
				data, _ = io.ReadAll(resp.Body)
				_ = resp.Body.Close()
			}
			if phase == "request" {
				if received.Load() != 0 {
					t.Fatalf("native-denied message reached origin: %d", received.Load())
				}
			} else {
				if err != nil || !bytes.Equal(data, rpcWire("safe")) {
					t.Fatalf("native response gate leaked or dropped safe message: %x %v", data, err)
				}
			}
		})
	}
}

func TestMessageHandlerHonorsAllowedHosts(t *testing.T) {
	f := firewall(t, config("http://127.0.0.1:1"), compiled(t, "enforce", "request", ""))
	f.cfg.AllowedHosts = []string{"allowed.example"}
	h, err := f.MessageHandler(false, true)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("POST", "https://forbidden.example/service/method", nil)
	r.ProtoMajor = 2
	r.Header.Set("Content-Type", "application/grpc")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code < 400 {
		t.Fatalf("stream wrapper bypassed allowedHosts: %d", w.Code)
	}
}

func TestMessageEvaluatorWebSocketSnapshotAndBothDirections(t *testing.T) {
	websocketBoundary(t, false)
}

func TestRoutedCompressedWebSocketSnapshotAndBothDirections(t *testing.T) {
	websocketBoundary(t, true)
}

func websocketBoundary(t *testing.T, routed bool) {
	originDone := make(chan struct{})
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer close(originDone)
		conn, rw, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		extension := ""
		if routed {
			extension = "Sec-WebSocket-Extensions: permessage-deflate; client_no_context_takeover; server_no_context_takeover\r\n"
		}
		_, _ = rw.WriteString("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n" + extension + "\r\n")
		_ = rw.Flush()
		_, _ = conn.Write([]byte{129, 2, 'h', 'i'})
		var request [8]byte
		if _, err := io.ReadFull(rw, request[:]); err != nil {
			t.Error(err)
			return
		}
		if request[0] != 129 || request[1] != 130 || request[6]^request[2] != 'o' || request[7]^request[3] != 'k' {
			t.Errorf("request gate changed payload: %x", request)
		}
		_, _ = conn.Write(append([]byte{129, 6}, []byte("secret")...))
	}))
	defer origin.Close()
	p := compiled(t, "enforce", "response", `Body contains "secret"`)
	f, bound, routeHandler := composedFirewall(t, config(origin.URL), p, routed)
	p = bound.Policy()
	var requestMessages, responseMessages atomic.Int64
	if err := f.SetEvaluator(func(ctx context.Context, snapshot *policy.Compiled, e policy.Event) (policy.Decision, error) {
		if snapshot != p || e.Protocol != "websocket" {
			t.Errorf("WebSocket evaluator lost snapshot/protocol: %p %s", snapshot, e.Protocol)
		}
		if e.Phase == "request" && e.Attributes["inspection.kind"] == "headers" {
			bound.SetPolicy(compiled(t, "enforce", "request", "true"))
		}
		if e.Attributes["inspection.kind"] == "message" {
			if e.Phase == "request" {
				requestMessages.Add(1)
				if e.Body != "" {
					t.Error("body-independent request phase copied Body")
				}
			} else {
				responseMessages.Add(1)
			}
		}
		return snapshot.Evaluate(e)
	}); err != nil {
		t.Fatal(err)
	}
	h, err := f.MessageHandler(true, false)
	if err != nil {
		t.Fatal(err)
	}
	if routed {
		h = routeHandler
	}
	proxy := httptest.NewServer(h)
	defer proxy.Close()
	conn, err := net.Dial("tcp", strings.TrimPrefix(proxy.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	extension := ""
	if routed {
		extension = "Sec-WebSocket-Extensions: permessage-deflate; client_no_context_takeover; server_no_context_takeover\r\n"
	}
	_, _ = io.WriteString(conn, "GET /chat HTTP/1.1\r\nHost: route.example\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"+extension+"\r\n")
	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, nil)
	if err != nil || resp.StatusCode != 101 {
		t.Fatalf("WebSocket handshake: %v %v", resp, err)
	}
	var safe [4]byte
	if _, err := io.ReadFull(reader, safe[:]); err != nil || !bytes.Equal(safe[:], []byte{129, 2, 'h', 'i'}) {
		t.Fatalf("response phase hook: %x %v", safe, err)
	}
	if routed {
		var compressed bytes.Buffer
		z, _ := flate.NewWriter(&compressed, flate.DefaultCompression)
		_, _ = z.Write([]byte("ok"))
		_ = z.Flush()
		payload := append([]byte(nil), compressed.Bytes()[:compressed.Len()-4]...)
		_ = z.Close()
		_, _ = conn.Write(append([]byte{193, 128 | byte(len(payload)), 0, 0, 0, 0}, payload...))
	} else {
		_, _ = conn.Write([]byte{129, 130, 0, 0, 0, 0, 'o', 'k'})
	}
	if b, err := reader.ReadByte(); err == nil {
		t.Fatalf("native-denied WebSocket header leaked: %x", b)
	}
	<-originDone
	if requestMessages.Load() != 1 || responseMessages.Load() != 2 {
		t.Fatalf("hook missed messages: requests=%d responses=%d", requestMessages.Load(), responseMessages.Load())
	}
}
