package waf

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"net/textproto"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestAdmissionLimit(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { close(entered); <-release }))
	defer origin.Close()
	c := config(origin.URL)
	c.MaxConcurrent = 1
	f := firewall(t, c, compiled(t, "enforce", "request", ""))
	done := make(chan struct{})
	go func() { defer close(done); call(f, "") }()
	<-entered
	w := call(f, "")
	close(release)
	<-done
	if w.Code != 503 {
		t.Fatalf("admission overflow %d", w.Code)
	}
}

func TestBodyDeadlineRejectsBeforeOrigin(t *testing.T) {
	var calls atomic.Int64
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1) }))
	defer origin.Close()
	c := config(origin.URL)
	c.BodyTimeout = "50ms"
	f := firewall(t, c, compiled(t, "enforce", "request", ""))
	proxy := httptest.NewServer(f)
	defer proxy.Close()
	conn, err := net.Dial("tcp", strings.TrimPrefix(proxy.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(time.Second))
	_, _ = fmt.Fprint(conn, "POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 10\r\n\r\nx")
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 408 || calls.Load() != 0 {
		t.Fatalf("status=%d calls=%d", resp.StatusCode, calls.Load())
	}
}

func TestEvaluationErrorFailClosedInMonitor(t *testing.T) {
	var calls atomic.Int64
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1) }))
	defer origin.Close()
	f := firewall(t, config(origin.URL), compiled(t, "monitor", "request", `Headers["X-Absent"][0] == "yes"`))
	w := call(f, "")
	if w.Code != 503 || calls.Load() != 0 {
		t.Fatalf("status=%d calls=%d", w.Code, calls.Load())
	}
}

func TestMetadataOnlyResponseCoverage(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, strings.Repeat("attack", 1000)) }))
	defer origin.Close()
	f := firewall(t, config(origin.URL), compiled(t, "enforce", "response", `Body contains "attack"`))
	w := call(f, "")
	if w.Code != 200 || w.Body.Len() != 6000 {
		t.Fatal("default response mode buffered or inspected body")
	}
	f.SetPolicy(compiled(t, "enforce", "response", `Status == 200`))
	w = call(f, "")
	if w.Code != 403 || strings.Contains(w.Body.String(), "attack") {
		t.Fatal("metadata denial leaked origin")
	}
}

func TestHTTP2UpstreamAndRedirectNotFollowed(t *testing.T) {
	var calls atomic.Int64
	var proto atomic.Int64
	origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		proto.Store(int64(r.ProtoMajor))
		w.Header().Set("Location", "/next")
		w.WriteHeader(302)
	}))
	origin.EnableHTTP2 = true
	origin.StartTLS()
	defer origin.Close()
	f := firewall(t, config(origin.URL), compiled(t, "enforce", "request", ""))
	// A test-only root pool keeps verification enabled for the test certificate.
	f.transport.TLSClientConfig.RootCAs = origin.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
	w := call(f, "")
	if w.Code != 302 || calls.Load() != 1 || proto.Load() != 2 || !f.transport.ForceAttemptHTTP2 || f.transport.Proxy != nil {
		t.Fatalf("status=%d calls=%d proto=%d", w.Code, calls.Load(), proto.Load())
	}
}

func TestAuditBoundedAndRedacted(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer origin.Close()
	f := firewall(t, config(origin.URL), compiled(t, "enforce", "request", `true`))
	for i := 0; i < 300; i++ {
		if call(f, "super-secret-body").Code != 403 {
			t.Fatal("deny failed")
		}
	}
	if len(f.audit) != 256 || f.stats.auditDropped.Load() != 44 {
		t.Fatal("audit queue unbounded")
	}
	b, err := json.Marshal(<-f.audit)
	if err != nil || strings.Contains(string(b), "secret") || strings.Contains(string(b), "test?") || strings.Contains(string(b), "192.0.2") {
		t.Fatalf("audit leaked %s", b)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := f.WriteAudit(ctx, io.Discard); err != context.Canceled {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	f.AdminHandler().ServeHTTP(w, httptest.NewRequest("GET", "/metrics", nil))
	if strings.Contains(w.Body.String(), "secret") || !strings.Contains(w.Body.String(), "waf_audit_dropped_total 44") {
		t.Fatal(w.Body.String())
	}
}

func TestDeniedResponseSuppressesEarlyHints(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Link", "</sensitive>; rel=preload")
		w.WriteHeader(103)
		_, _ = io.WriteString(w, "attack")
	}))
	defer origin.Close()
	c := config(origin.URL)
	c.InspectResponse = true
	f := firewall(t, c, compiled(t, "enforce", "response", `Body contains "attack"`))
	proxy := httptest.NewServer(f)
	defer proxy.Close()
	var hints atomic.Int64
	r, _ := http.NewRequest("GET", proxy.URL, nil)
	r = r.WithContext(httptrace.WithClientTrace(r.Context(), &httptrace.ClientTrace{Got1xxResponse: func(_ int, _ textproto.MIMEHeader) error { hints.Add(1); return nil }}))
	resp, err := http.DefaultClient.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 403 || hints.Load() != 0 || resp.Header.Get("Link") != "" {
		t.Fatalf("denial leaked hints: status=%d hints=%d headers=%v", resp.StatusCode, hints.Load(), resp.Header)
	}
}

func TestResponseInspectionDeadline(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Secret", "origin")
		w.WriteHeader(200)
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	}))
	defer origin.Close()
	c := config(origin.URL)
	c.InspectResponse = true
	c.BodyTimeout = "50ms"
	f := firewall(t, c, compiled(t, "enforce", "request", ""))
	w := call(f, "")
	if w.Code != 502 || w.Header().Get("X-Secret") != "" {
		t.Fatalf("unbounded response or leaked headers: %d %v", w.Code, w.Header())
	}
}

func TestEarlyRejectDoesNotDrainUnsentBody(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("rejected host reached origin") }))
	defer origin.Close()
	c := config(origin.URL)
	c.AllowedHosts = []string{"allowed.example"}
	f := firewall(t, c, compiled(t, "enforce", "request", ""))
	proxy := httptest.NewServer(f)
	defer proxy.Close()
	conn, err := net.Dial("tcp", strings.TrimPrefix(proxy.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(time.Second))
	_, _ = fmt.Fprint(conn, "POST / HTTP/1.1\r\nHost: forbidden.example\r\nContent-Length: 10\r\n\r\n")
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 421 {
		t.Fatal(resp.StatusCode)
	}
}

func TestBodylessResponsesPreserveRepresentationMetadata(t *testing.T) {
	for _, tc := range []struct {
		method string
		status int
	}{{"HEAD", 200}, {"GET", 304}, {"GET", 204}} {
		t.Run(fmt.Sprintf("%s-%d", tc.method, tc.status), func(t *testing.T) {
			origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Encoding", "gzip")
				w.Header().Set("ETag", `"original"`)
				w.Header().Set("Content-Length", "100")
				w.WriteHeader(tc.status)
			}))
			defer origin.Close()
			c := config(origin.URL)
			c.InspectResponse = true
			c.MaxResponseBytes = 4
			f := firewall(t, c, compiled(t, "enforce", "request", ""))
			r := httptest.NewRequest(tc.method, "http://route.example/", nil)
			w := httptest.NewRecorder()
			f.ServeHTTP(w, r)
			if w.Code != tc.status || w.Header().Get("ETag") != `"original"` || w.Body.Len() != 0 {
				t.Fatalf("bodyless response: %d %v %q", w.Code, w.Header(), w.Body.String())
			}
			if tc.method == "HEAD" && (w.Header().Get("Content-Length") != "100" || w.Header().Get("Content-Encoding") != "gzip") {
				t.Fatal(w.Header())
			}
		})
	}
}
