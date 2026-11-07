package waf

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/internal/policy"
)

func compiled(t *testing.T, mode, phase, expression string) *policy.Compiled {
	t.Helper()
	b := policy.Bundle{Version: "v1", ID: "test", Mode: mode, Default: "allow"}
	if expression != "" {
		b.Rules = []policy.Rule{{ID: "deny-test", Phase: phase, Expression: expression, Action: "deny", Status: 403}}
	}
	p, err := policy.Compile(b)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func config(origin string) Config {
	return Config{Version: "netcap-firewall/v1", Listen: "127.0.0.1:8080", AdminListen: "127.0.0.1:8081", Upstream: origin, MaxBodyBytes: 1024, MaxResponseBytes: 1024, MaxConcurrent: 8, BodyTimeout: "2s"}
}
func firewall(t *testing.T, c Config, p *policy.Compiled) *Firewall {
	t.Helper()
	f, err := New(c, p)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	return f
}
func call(f *Firewall, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("POST", "http://route.example/test?secret=hidden", strings.NewReader(body))
	r.RemoteAddr = "192.0.2.1:1234"
	w := httptest.NewRecorder()
	f.ServeHTTP(w, r)
	return w
}

func TestBodyLateDenialNeverContactsOrigin(t *testing.T) {
	var calls atomic.Int64
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		_, _ = io.Copy(io.Discard, r.Body)
		_, _ = io.WriteString(w, "origin")
	}))
	defer origin.Close()
	f := firewall(t, config(origin.URL), compiled(t, "enforce", "request", `Body contains "attack"`))
	proxy := httptest.NewServer(f)
	defer proxy.Close()
	conn, err := net.Dial("tcp", strings.TrimPrefix(proxy.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_, _ = fmt.Fprint(conn, "POST / HTTP/1.1\r\nHost: route.example\r\nContent-Length: 12\r\n\r\nnormal")
	time.Sleep(40 * time.Millisecond)
	if calls.Load() != 0 {
		t.Fatal("origin contacted before body completed")
	}
	_, _ = fmt.Fprint(conn, "attack")
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 403 || calls.Load() != 0 {
		t.Fatalf("status=%d origin calls=%d", resp.StatusCode, calls.Load())
	}
}

func TestMonitorAndNormalization(t *testing.T) {
	seen := make(chan string, 1)
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		seen <- fmt.Sprintf("%s|%s|%d|%s", r.Host, r.Header.Get("Content-Encoding"), r.ContentLength, b)
		_, _ = io.WriteString(w, "forwarded")
	}))
	defer origin.Close()
	f := firewall(t, config(origin.URL), compiled(t, "monitor", "request", `Body contains "attack"`))
	var b bytes.Buffer
	z := gzip.NewWriter(&b)
	_, _ = z.Write([]byte("attack"))
	_ = z.Close()
	r := httptest.NewRequest("POST", "http://route.example/", &b)
	r.Header.Set("Content-Encoding", "gzip")
	w := httptest.NewRecorder()
	f.ServeHTTP(w, r)
	if w.Code != 200 || <-seen != "route.example||6|attack" || f.stats.wouldDeny.Load() != 1 {
		t.Fatalf("status %d would deny %d", w.Code, f.stats.wouldDeny.Load())
	}
}

func TestLimitsAndMalformedBodies(t *testing.T) {
	var calls atomic.Int64
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1) }))
	defer origin.Close()
	f := firewall(t, config(origin.URL), compiled(t, "monitor", "request", ""))
	var bomb bytes.Buffer
	z := gzip.NewWriter(&bomb)
	_, _ = z.Write(bytes.Repeat([]byte("x"), 8192))
	_ = z.Close()
	for _, tc := range []struct {
		name, body, encoding string
		status               int
	}{{"wire", strings.Repeat("x", 1025), "", 413}, {"bomb", bomb.String(), "gzip", 413}, {"bad gzip", "junk", "gzip", 400}, {"unsupported", "data", "br", 415}, {"chain", "data", "gzip, gzip", 415}, {"truncated", bomb.String()[:bomb.Len()-4], "gzip", 413}} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest("POST", "http://route.example/", strings.NewReader(tc.body))
			r.ContentLength = -1
			if tc.encoding != "" {
				r.Header.Set("Content-Encoding", tc.encoding)
			}
			w := httptest.NewRecorder()
			f.ServeHTTP(w, r)
			if w.Code != tc.status {
				t.Fatalf("got %d want %d", w.Code, tc.status)
			}
		})
	}
	if calls.Load() != 0 {
		t.Fatalf("origin received %d rejected requests", calls.Load())
	}
}

func TestResponseDenialLeaksNoHeadersOrBody(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Origin-Secret", "secret")
		_, _ = io.WriteString(w, "private attack data")
	}))
	defer origin.Close()
	c := config(origin.URL)
	c.InspectResponse = true
	f := firewall(t, c, compiled(t, "enforce", "response", `Body contains "attack"`))
	w := call(f, "")
	if w.Code != 403 || strings.Contains(w.Body.String(), "private") || w.Header().Get("X-Origin-Secret") != "" {
		t.Fatalf("response leaked: %d %v %q", w.Code, w.Header(), w.Body.String())
	}
	c.MaxResponseBytes = 4
	g := firewall(t, c, compiled(t, "monitor", "request", ""))
	w = call(g, "")
	if w.Code != 502 || strings.Contains(w.Body.String(), "private") {
		t.Fatal("response limit failed")
	}
}

func TestForwardingTrustAndHost(t *testing.T) {
	seen := make(chan http.Header, 4)
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { h := r.Header.Clone(); h.Set("Host", r.Host); seen <- h }))
	defer origin.Close()
	c := config(origin.URL)
	c.TrustedProxyCIDRs = []string{"10.0.0.0/8"}
	c.AllowedHosts = []string{"route.example"}
	f := firewall(t, c, compiled(t, "enforce", "request", ""))
	for _, tc := range []struct{ peer, xff, want string }{{"192.0.2.1:1", "1.1.1.1", "192.0.2.1"}, {"10.1.1.1:1", "1.1.1.1, 192.0.2.2, 10.2.2.2", "192.0.2.2"}} {
		r := httptest.NewRequest("GET", "http://route.example/", nil)
		r.RemoteAddr = tc.peer
		r.Header.Set("X-Forwarded-For", tc.xff)
		r.Header.Set("Forwarded", "for=evil")
		r.Header.Set("X-Real-IP", "evil")
		r.Header.Set("X-Forwarded-Proto", "https")
		r.Header.Set("X-Forwarded-Evil", "evil")
		w := httptest.NewRecorder()
		f.ServeHTTP(w, r)
		if w.Code != 200 {
			t.Fatal(w.Code)
		}
		h := <-seen
		if h.Get("X-Forwarded-For") != tc.want || h.Get("Forwarded") != "" || h.Get("X-Real-IP") != "" || h.Get("X-Forwarded-Evil") != "" || h.Get("X-Forwarded-Proto") != "http" || h.Get("Host") != "route.example" {
			t.Fatal(h)
		}
	}
}

func TestConcurrentReloadAndDrain(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "ok") }))
	defer origin.Close()
	f := firewall(t, config(origin.URL), compiled(t, "enforce", "request", ""))
	a := compiled(t, "enforce", "request", "")
	b := compiled(t, "enforce", "request", `true`)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 30; j++ {
				f.SetPolicy(a)
				f.SetPolicy(b)
				w := call(f, "")
				if w.Code != 200 && w.Code != 403 {
					t.Errorf("unexpected %d", w.Code)
				}
			}
		}()
	}
	wg.Wait()
	f.SetDraining(true)
	if call(f, "").Code != 503 {
		t.Fatal("drain accepted request")
	}
	w := httptest.NewRecorder()
	f.AdminHandler().ServeHTTP(w, httptest.NewRequest("GET", "/readyz", nil))
	if w.Code != 503 {
		t.Fatal("ready while draining")
	}
}

func TestSSEStreamsWithoutFullBuffer(t *testing.T) {
	release := make(chan struct{})
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: first\n\n")
		w.(http.Flusher).Flush()
		<-release
	}))
	f := firewall(t, config(origin.URL), compiled(t, "enforce", "request", ""))
	proxy := httptest.NewServer(f)
	t.Cleanup(func() {
		close(release)
		proxy.CloseClientConnections()
		proxy.Close()
		origin.CloseClientConnections()
		origin.Close()
	})
	client := &http.Client{Timeout: time.Second}
	resp, err := client.Get(proxy.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	line, err := bufio.NewReader(resp.Body).ReadString('\n')
	if err != nil || line != "data: first\n" {
		t.Fatalf("stream %q %v", line, err)
	}
}

func TestWebSocketUpgradeTunnel(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, rw, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = rw.WriteString("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
		_ = rw.Flush()
		b := make([]byte, 4)
		if _, err = io.ReadFull(rw, b); err == nil {
			_, _ = conn.Write(b)
		}
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
	_, _ = fmt.Fprint(conn, "GET / HTTP/1.1\r\nHost: route.example\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
	rd := bufio.NewReader(conn)
	resp, err := http.ReadResponse(rd, nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 101 {
		t.Fatal(resp.StatusCode)
	}
	_, _ = conn.Write([]byte("ping"))
	b := make([]byte, 4)
	_, err = io.ReadFull(rd, b)
	if err != nil || string(b) != "ping" {
		t.Fatalf("tunnel %q %v", b, err)
	}
}
