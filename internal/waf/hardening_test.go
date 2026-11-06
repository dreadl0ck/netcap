package waf

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/internal/policy"
)

func rawRequest(t *testing.T, server, raw string) *http.Response {
	t.Helper()
	c, err := net.Dial("tcp", strings.TrimPrefix(server, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	_ = c.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err = io.WriteString(c, raw); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	return resp
}

func TestRawFramingAndParserLimits(t *testing.T) {
	var calls atomic.Int64
	seen := make(chan string, 2)
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		b, _ := io.ReadAll(r.Body)
		seen <- fmt.Sprintf("%d/%d/%d/%s", len(r.Header.Values("Content-Length")), len(r.TransferEncoding), r.ContentLength, b)
	}))
	defer origin.Close()
	f := firewall(t, config(origin.URL), compiled(t, "enforce", "request", `Body contains "attack"`))
	proxy := httptest.NewUnstartedServer(f)
	proxy.Config.MaxHeaderBytes = 1024
	proxy.Config.ReadHeaderTimeout = time.Second
	proxy.Start()
	defer proxy.Close()
	for _, tc := range []struct {
		name, raw string
		status    int
	}{
		{"conflicting-length", "POST / HTTP/1.1\r\nHost: route.example\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\nxx", 400},
		{"comma-length", "POST / HTTP/1.1\r\nHost: route.example\r\nContent-Length: 1, 1\r\n\r\nx", 400},
		{"invalid-transfer", "POST / HTTP/1.1\r\nHost: route.example\r\nTransfer-Encoding: chunked, gzip\r\n\r\n", 501},
		{"CLTE-denied", "POST / HTTP/1.1\r\nHost: route.example\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n6\r\nattack\r\n0\r\n\r\n", 403},
		{"bad-chunk", "POST / HTTP/1.1\r\nHost: route.example\r\nTransfer-Encoding: chunked\r\n\r\nz\r\nattack\r\n0\r\n\r\n", 400},
		{"header-cap", "GET / HTTP/1.1\r\nHost: route.example\r\nX-Large: " + strings.Repeat("x", 8192) + "\r\n\r\n", 431},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := calls.Load()
			resp := rawRequest(t, proxy.URL, tc.raw)
			if resp.StatusCode != tc.status || calls.Load() != before {
				t.Fatalf("status=%d calls=%d", resp.StatusCode, calls.Load()-before)
			}
		})
	}
	// net/http accepts identical duplicate lengths and CLTE under RFC 9112 by
	// discarding the old framing. Only one newly calculated length reaches origin.
	for _, raw := range []string{
		"POST / HTTP/1.1\r\nHost: route.example\r\nContent-Length: 4\r\nContent-Length: 4\r\nConnection: close\r\n\r\nsafe",
		"POST / HTTP/1.1\r\nHost: route.example\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n4\r\nsafe\r\n0\r\n\r\n",
	} {
		resp := rawRequest(t, proxy.URL, raw)
		if resp.StatusCode != 200 {
			t.Fatal(resp.StatusCode)
		}
		if got := <-seen; got != "1/0/4/safe" {
			t.Fatal("ambiguous upstream framing: ", got)
		}
	}
}

func TestTruncatedOriginNeverLeaksBufferedResponse(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, rw, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = rw.WriteString("HTTP/1.1 200 OK\r\nContent-Length: 100\r\nX-Secret: hidden\r\n\r\nprivate")
		_ = rw.Flush()
	}))
	defer origin.Close()
	c := config(origin.URL)
	c.InspectResponse = true
	f := firewall(t, c, compiled(t, "monitor", "request", ""))
	w := call(f, "")
	if w.Code != 502 || strings.Contains(w.Body.String(), "private") || w.Header().Get("X-Secret") != "" {
		t.Fatalf("incomplete response leaked %d %v %q", w.Code, w.Header(), w.Body.String())
	}
}

func TestHTTPProtocolScopeBothPhases(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer origin.Close()
	for _, phase := range []string{"request", "response"} {
		f := firewall(t, config(origin.URL), compiled(t, "enforce", phase, `Protocol == "http"`))
		if call(f, "").Code != 403 {
			t.Fatalf("missing Protocol in %s", phase)
		}
	}
}

func TestNativeWorkBudgetRejectsFullBodyBeforeOrigin(t *testing.T) {
	var calls atomic.Int64
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1) }))
	defer origin.Close()
	b := policy.Bundle{Version: "v1", ID: "budget", Mode: "monitor", Default: "allow", Rules: []policy.Rule{{ID: "expensive", Phase: "request", Action: "deny", Expression: `false and Body matches "a{1000}"`}}}
	p, err := policy.Compile(b)
	if err != nil {
		t.Fatal(err)
	}
	c := config(origin.URL)
	c.MaxBodyBytes = 1 << 20
	f := firewall(t, c, p)
	w := call(f, strings.Repeat("a", 1<<20))
	if w.Code != 503 || calls.Load() != 0 || f.stats.errors.Load() != 1 {
		t.Fatalf("budget status=%d calls=%d errors=%d", w.Code, calls.Load(), f.stats.errors.Load())
	}
}

func TestHTTP2BodyDeadlineIsStreamLocal(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "ok") }))
	defer origin.Close()
	c := config(origin.URL)
	c.BodyTimeout = "150ms"
	f := firewall(t, c, compiled(t, "enforce", "request", ""))
	proxy := httptest.NewUnstartedServer(f)
	proxy.EnableHTTP2 = true
	var connections atomic.Int64
	proxy.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			connections.Add(1)
		}
	}
	proxy.StartTLS()
	defer proxy.Close()
	client := proxy.Client()
	client.Timeout = 2 * time.Second
	client.Transport.(*http.Transport).MaxConnsPerHost = 1
	reader, writer := io.Pipe()
	defer reader.Close()
	defer writer.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		req, _ := http.NewRequest("POST", proxy.URL, reader)
		resp, err := client.Do(req)
		if err == nil {
			_ = resp.Body.Close()
		}
	}()
	deadline := time.Now().Add(time.Second)
	for f.stats.requests.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	for i := 0; i < 2; i++ {
		resp, err := client.Get(proxy.URL)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.ProtoMajor != 2 || resp.StatusCode != 200 || string(b) != "ok" {
			t.Fatalf("unrelated stream failed: %s %d %q", resp.Proto, resp.StatusCode, b)
		}
		if i == 0 {
			<-done
		}
	}
	if connections.Load() != 1 {
		t.Fatalf("test did not share one HTTP/2 connection: %d", connections.Load())
	}
}

func TestCloseTerminatesIdleUpgrade(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, rw, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = rw.WriteString("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
		_ = rw.Flush()
		_, _ = io.Copy(io.Discard, conn)
	}))
	defer origin.Close()
	f := firewall(t, config(origin.URL), compiled(t, "enforce", "request", ""))
	proxy := httptest.NewServer(f)
	defer proxy.Close()
	conn, err := net.Dial("tcp", strings.TrimPrefix(proxy.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(time.Second))
	_, _ = io.WriteString(conn, "GET / HTTP/1.1\r\nHost: route.example\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
	rd := bufio.NewReader(conn)
	resp, err := http.ReadResponse(rd, nil)
	if err != nil || resp.StatusCode != 101 {
		t.Fatal(resp, err)
	}
	f.SetDraining(true)
	if call(f, "").Code != 503 || len(f.slots) != 1 {
		t.Fatal("drain did not account for active upgrade")
	}
	_ = f.Close()
	_, err = rd.ReadByte()
	if err == nil {
		t.Fatal("idle hijacked connection survived Close")
	}
	deadline := time.Now().Add(time.Second)
	for len(f.slots) != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if len(f.slots) != 0 {
		t.Fatal("upgrade retained admission slot after Close")
	}
}

func BenchmarkNativeBudgetFullBody(b *testing.B) {
	p, err := policy.Compile(policy.Bundle{Version: "v1", ID: "budget", Mode: "monitor", Default: "allow", Rules: []policy.Rule{{ID: "expensive", Phase: "request", Action: "deny", Expression: `false and Body matches "a{1000}"`}}})
	if err != nil {
		b.Fatal(err)
	}
	c := config("http://127.0.0.1:1")
	c.MaxBodyBytes = 1 << 20
	f, err := New(c, p)
	if err != nil {
		b.Fatal(err)
	}
	defer f.Close()
	body := strings.Repeat("a", 1<<20)
	b.ReportAllocs()
	b.SetBytes(int64(len(body)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest("POST", "http://route.example/", strings.NewReader(body))
		w := httptest.NewRecorder()
		f.ServeHTTP(w, req)
		if w.Code != 503 {
			b.Fatal(w.Code)
		}
	}
}
