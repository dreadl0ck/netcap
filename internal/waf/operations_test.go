package waf

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestOperationsMeasuresDecisionForwardingWithoutTrafficLabels(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { time.Sleep(3 * time.Millisecond); w.Write([]byte("ok")) }))
	defer origin.Close()
	p := compiled(t, "enforce", "request", `Path contains "denied"`)
	f := firewall(t, config(origin.URL), p)
	for i := range 30 {
		path := "/attacker/" + strings.Repeat("x", i)
		r := httptest.NewRequest("GET", "http://route.example"+path+"?secret=never-export", nil)
		r.RemoteAddr = "192.0.2.1:1234"
		w := httptest.NewRecorder()
		f.ServeHTTP(w, r)
		if w.Code != 200 {
			t.Fatal(w.Code)
		}
	}
	metrics, err := f.Operations.Registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	stages := map[string]bool{}
	for _, family := range metrics {
		if family.GetName() != "netcap_firewall_operation_duration_seconds" {
			continue
		}
		for _, m := range family.Metric {
			for _, l := range m.Label {
				stages[l.GetValue()] = true
			}
			if m.Histogram.GetSampleCount() == 0 {
				t.Fatal("empty histogram")
			}
		}
	}
	for _, stage := range []string{"decision", "queue", "forwarding"} {
		if !stages[stage] {
			t.Fatal("missing runtime stage", stage)
		}
	}
	w := httptest.NewRecorder()
	f.Operations.Handler().ServeHTTP(w, httptest.NewRequest("GET", "/metrics", nil))
	if strings.Contains(w.Body.String(), "192.0.2.1") || strings.Contains(w.Body.String(), "never-export") || strings.Contains(w.Body.String(), "attacker") {
		t.Fatal("traffic labels leaked")
	}
	if strings.Contains(w.Body.String(), `revision=`) || f.Operations.Status().ActiveRevision != p.Revision() {
		t.Fatal("revision must be status-only")
	}
	origin.Close()
	// Origin availability is deliberately independent of local readiness.
	call(f, "")
	if !f.ready() {
		t.Fatal("origin outage made local readiness fail")
	}
}
