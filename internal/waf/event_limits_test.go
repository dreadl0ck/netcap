package waf

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/dreadl0ck/netcap/internal/policy"
)

func TestMaximumInspectionBodiesFitEmptyPolicy(t *testing.T) {
	if MaxInspectionBodyBytes+(maxInspectionFieldBytes*5)+maxInspectionHeaderBytes+64 > policy.MaxEventBytes {
		t.Fatal("WAF body and metadata bounds exceed native event budget")
	}
	body := strings.Repeat("a", int(MaxInspectionBodyBytes))
	var calls atomic.Int64
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		b, err := io.ReadAll(r.Body)
		if err != nil || string(b) != body {
			t.Error("maximum request body changed or truncated")
		}
		w.Header().Set("X-Padding", strings.Repeat("r", 30<<10))
		_, _ = io.WriteString(w, body)
	}))
	defer origin.Close()
	c := config(origin.URL)
	c.MaxBodyBytes = MaxInspectionBodyBytes
	c.MaxResponseBytes = MaxInspectionBodyBytes
	c.InspectResponse = true
	f := firewall(t, c, compiled(t, "enforce", "request", ""))
	r := httptest.NewRequest("POST", "http://route.example/?padding="+strings.Repeat("q", 60<<10), strings.NewReader(body))
	r.Header.Set("X-Padding", strings.Repeat("h", 30<<10))
	w := httptest.NewRecorder()
	f.ServeHTTP(w, r)
	if w.Code != 200 || calls.Load() != 1 || w.Body.String() != body || f.stats.errors.Load() != 0 {
		t.Fatalf("boundary body failed: status=%d calls=%d response bytes=%d evaluation errors=%d", w.Code, calls.Load(), w.Body.Len(), f.stats.errors.Load())
	}
}

func TestOversizedRequestMetadataRejectsBeforeOrigin(t *testing.T) {
	var calls atomic.Int64
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1) }))
	defer origin.Close()
	f := firewall(t, config(origin.URL), compiled(t, "enforce", "request", ""))
	for _, tc := range []struct {
		name   string
		fill   func(*http.Request)
		status int
	}{
		{"header-bytes", func(r *http.Request) { r.Header.Set("X-Padding", strings.Repeat("h", maxInspectionHeaderBytes)) }, 431},
		{"header-names", func(r *http.Request) {
			for i := 0; i < 129; i++ {
				r.Header.Set(fmt.Sprint("X-", i), "v")
			}
		}, 431},
		{"header-values", func(r *http.Request) { r.Header["X-Values"] = make([]string, 1025) }, 431},
		{"header-name-length", func(r *http.Request) { r.Header.Set(strings.Repeat("X", 1025), "v") }, 431},
		{"query", func(r *http.Request) { r.URL.RawQuery = "q=" + strings.Repeat("x", maxInspectionFieldBytes) }, 414},
		{"path", func(r *http.Request) { r.URL.Path = "/" + strings.Repeat("x", maxInspectionFieldBytes) }, 414},
		{"host", func(r *http.Request) { r.Host = strings.Repeat("h", maxInspectionFieldBytes+1) }, 414},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "http://route.example/", nil)
			tc.fill(r)
			w := httptest.NewRecorder()
			f.ServeHTTP(w, r)
			if w.Code != tc.status {
				t.Fatalf("got %d want %d", w.Code, tc.status)
			}
		})
	}
	if calls.Load() != 0 || f.stats.errors.Load() != 0 {
		t.Fatalf("oversized metadata reached origin or evaluator: calls=%d errors=%d", calls.Load(), f.stats.errors.Load())
	}
}

func TestOversizedResponseHeadersNeverReachEvaluatorOrClient(t *testing.T) {
	for _, names := range []bool{false, true} {
		t.Run(fmt.Sprint("many-names=", names), func(t *testing.T) {
			origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if names {
					for i := 0; i < 129; i++ {
						w.Header().Set(fmt.Sprint("X-", i), "v")
					}
				} else {
					w.Header().Set("X-Padding", strings.Repeat("r", maxInspectionHeaderBytes+1))
				}
				_, _ = io.WriteString(w, "private")
			}))
			defer origin.Close()
			f := firewall(t, config(origin.URL), compiled(t, "enforce", "request", ""))
			w := call(f, "")
			if w.Code != 502 || w.Header().Get("X-Padding") != "" || strings.Contains(w.Body.String(), "private") || f.stats.errors.Load() != 0 {
				t.Fatalf("response metadata leaked or caused native failure: %d errors=%d", w.Code, f.stats.errors.Load())
			}
		})
	}
}
