//go:build coraza

package waf

import (
	"bytes"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	coreruleset "github.com/corazawaf/coraza-coreruleset/v4"
	"github.com/corazawaf/coraza/v3"
)

func TestCorazaCRSBodyEnforcementAndMonitor(t *testing.T) {
	var calls atomic.Int64
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); _, _ = io.WriteString(w, "origin") }))
	defer origin.Close()
	for _, mode := range []string{"enforce", "monitor"} {
		t.Run(mode, func(t *testing.T) {
			c := config(origin.URL)
			c.CorazaCRS = true
			f := firewall(t, c, compiled(t, mode, "request", ""))
			r := httptest.NewRequest("POST", "http://route.example/", strings.NewReader(`field=<script>alert(1)</script>`))
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			r.Header.Set("User-Agent", "WAF integration test")
			r.Header.Set("Accept", "*/*")
			w := httptest.NewRecorder()
			before := calls.Load()
			f.ServeHTTP(w, r)
			if mode == "enforce" {
				if w.Code != 403 || calls.Load() != before {
					t.Fatalf("CRS bypass: status=%d calls=%d", w.Code, calls.Load()-before)
				}
			} else if w.Code != 200 || calls.Load() != before+1 || f.stats.wouldDeny.Load() != 1 {
				t.Fatalf("monitor: status=%d calls=%d would=%d", w.Code, calls.Load()-before, f.stats.wouldDeny.Load())
			}
		})
	}
}

func TestCorazaFTWAndStructuralFailures(t *testing.T) {
	var calls atomic.Int64
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); _, _ = io.WriteString(w, "ok") }))
	defer origin.Close()
	multipartBody := func(value string) (string, string) {
		var b bytes.Buffer
		m := multipart.NewWriter(&b)
		_ = m.WriteField("message", value)
		_ = m.Close()
		return b.String(), m.FormDataContentType()
	}
	benignMultipart, multiType := multipartBody("Hello world")
	attackMultipart, attackMultiType := multipartBody("<script>alert(1)</script>")
	cases := []struct {
		name, path, body, ct string
		status               int
	}{
		{"benign-query", "/?q=coffee%20tea&tag=one&tag=two", "", "", 200},
		{"sqli-query", "/?q=1%27%20OR%20%271%27=%271", "", "", 403},
		{"traversal-query", "/?file=..%2f..%2fetc%2fpasswd", "", "", 403},
		{"benign-json", "/", `{"message":"Hello world","values":[1,2,3]}`, "application/json", 200},
		{"json-xss", "/", `{"message":"<script>alert(1)</script>"}`, "application/json", 403},
		{"vendor-json-xss", "/", `{"message":"<script>alert(1)</script>"}`, "application/problem+json", 403},
		{"json-parser-error", "/", `{"message":`, "application/json", 400},
		{"json-trailing-document", "/", `{} {}`, "application/json", 400},
		{"json-depth", "/", strings.Repeat("[", 70) + "0" + strings.Repeat("]", 70), "application/json", 400},
		{"benign-xml", "/", `<message>Hello world</message>`, "application/xml", 200},
		{"xml-parser-error", "/", `<message>broken`, "application/xml", 400},
		{"benign-multipart", "/", benignMultipart, multiType, 200},
		{"multipart-xss", "/", attackMultipart, attackMultiType, 403},
		{"broken-multipart", "/", "--missing\r\n", "multipart/form-data; boundary=expected", 400},
		{"bad-form-escape", "/", "a=%zz", "application/x-www-form-urlencoded", 400},
		{"argument-cap-query", "/?" + strings.TrimSuffix(strings.Repeat("a=1&", 1001), "&"), "", "", 413},
		{"argument-cap-form", "/", strings.TrimSuffix(strings.Repeat("a=1&", 1001), "&"), "application/x-www-form-urlencoded", 413},
		{"argument-cap-json", "/", "[" + strings.TrimSuffix(strings.Repeat("1,", 1001), ",") + "]", "application/json", 413},
	}
	for _, mode := range []string{"enforce", "monitor"} {
		c := config(origin.URL)
		c.CorazaCRS = true
		c.MaxBodyBytes = 16384
		f := firewall(t, c, compiled(t, mode, "request", ""))
		for _, tc := range cases {
			t.Run(mode+"/"+tc.name, func(t *testing.T) {
				r := httptest.NewRequest("POST", "http://route.example"+tc.path, strings.NewReader(tc.body))
				r.Header.Set("User-Agent", "WAF integration test")
				r.Header.Add("Accept", "text/plain")
				r.Header.Add("Accept", "application/json")
				if tc.ct != "" {
					r.Header.Set("Content-Type", tc.ct)
				}
				w := httptest.NewRecorder()
				before := calls.Load()
				f.ServeHTTP(w, r)
				want := tc.status
				if mode == "monitor" && want == 403 {
					want = 200
				}
				if w.Code != want {
					t.Fatalf("got %d want %d, body=%q", w.Code, want, w.Body.String())
				}
				if want == 200 && calls.Load() != before+1 || want != 200 && calls.Load() != before {
					t.Fatalf("unexpected origin calls %d for status %d", calls.Load()-before, w.Code)
				}
			})
		}
	}
}

func TestCorazaQueryAndLengthAreFedExactlyOnce(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer origin.Close()
	c := config(origin.URL)
	c.CorazaCRS = true
	f := firewall(t, c, compiled(t, "enforce", "request", ""))
	directives := corazaDirectives(c) + `
SecRule &ARGS_GET "!@eq 1" "id:10000003,phase:1,deny,status:400,nolog"
SecRule &REQUEST_HEADERS:Content-Length "!@eq 1" "id:10000004,phase:1,deny,status:400,nolog"
`
	w, err := coraza.NewWAF(coraza.NewWAFConfig().WithRootFS(coreruleset.FS).WithDirectives(directives))
	if err != nil {
		t.Fatal(err)
	}
	f.engine = &corazaEngine{waf: w}
	proxy := httptest.NewServer(f)
	defer proxy.Close()
	resp := rawRequest(t, proxy.URL, "POST /?name=alice HTTP/1.1\r\nHost: route.example\r\nUser-Agent: test\r\nAccept: */*\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 4\r\nContent-Length: 4\r\nConnection: close\r\n\r\na=ok")
	if resp.StatusCode != 200 {
		t.Fatal("duplicated connector inputs: ", resp.StatusCode)
	}
}

func TestMonitorEarlyCRSInterruptionCannotSkipMalformedBody(t *testing.T) {
	var calls atomic.Int64
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1) }))
	defer origin.Close()
	c := config(origin.URL)
	c.CorazaCRS = true
	f := firewall(t, c, compiled(t, "monitor", "request", ""))
	r := httptest.NewRequest("POST", "http://route.example/", strings.NewReader(`{"broken":`))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("User-Agent", "sqlmap/1.0")
	w := httptest.NewRecorder()
	f.ServeHTTP(w, r)
	if w.Code != 400 || calls.Load() != 0 {
		t.Fatalf("monitor parser bypass: %d calls=%d", w.Code, calls.Load())
	}
}

func TestCorazaEarlyInterruptionStillRunsParserInMonitor(t *testing.T) {
	c := config("http://origin.example")
	c.CorazaCRS = true
	engine, err := newInspectionEngine(c)
	if err != nil {
		t.Fatal(err)
	}
	e := engine.(*corazaEngine)
	w, err := coraza.NewWAF(coraza.NewWAFConfig().WithRootFS(coreruleset.FS).WithDirectives(corazaDirectives(c) + `SecRule REQUEST_METHOD "@streq POST" "id:10000005,phase:1,deny,status:403,nolog"`))
	if err != nil {
		t.Fatal(err)
	}
	e.waf = w
	for _, tc := range []struct {
		body   string
		status int
	}{{`{"broken":`, 400}, {`{"safe":"hello"}`, 403}} {
		r := httptest.NewRequest("POST", "http://route.example/", nil)
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("User-Agent", "test")
		r.Header.Set("Accept", "*/*")
		tx, status, err := e.request(r, strings.NewReader(tc.body), "192.0.2.1", true)
		if tx != nil {
			_ = tx.Close()
		}
		if err != nil || status != tc.status {
			t.Fatalf("parser fallback status=%d want=%d err=%v", status, tc.status, err)
		}
	}
}

func TestCorazaInspectedResponseAtExactLimit(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "safe")
	}))
	defer origin.Close()
	c := config(origin.URL)
	c.CorazaCRS = true
	c.InspectResponse = true
	c.MaxResponseBytes = 4
	f := firewall(t, c, compiled(t, "enforce", "request", ""))
	r := httptest.NewRequest("GET", "http://route.example/", nil)
	r.Header.Set("User-Agent", "WAF integration test")
	r.Header.Set("Accept", "*/*")
	w := httptest.NewRecorder()
	f.ServeHTTP(w, r)
	if w.Code != 200 || w.Body.String() != "safe" {
		t.Fatalf("exact response limit status=%d body=%q", w.Code, w.Body.String())
	}
}
