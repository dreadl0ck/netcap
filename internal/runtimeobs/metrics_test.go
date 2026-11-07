package runtimeobs

import (
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

func TestMeasuredLatencyAndAttackerCardinality(t *testing.T) {
	m := New()
	other := New()
	start := time.Now()
	time.Sleep(2 * time.Millisecond)
	m.Observe("decision", start, "deny")
	for i := range 1000 {
		attacker := fmt.Sprintf("192.0.2.%d/path?secret=%d", i, i)
		m.Observe(attacker, start, attacker)
		m.Health(false, attacker)
		m.Revision(attacker)
	}
	families, err := m.Registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range families {
		if len(f.Metric) > 2 {
			t.Fatalf("unbounded series: %s %d", f.GetName(), len(f.Metric))
		}
		for _, metric := range f.Metric {
			for _, label := range metric.Label {
				if strings.Contains(label.GetValue(), "secret") || label.GetName() == "revision" {
					t.Fatal("attacker/revision label")
				}
			}
		}
		if f.GetName() == "netcap_firewall_operation_duration_seconds" {
			for _, metric := range f.Metric {
				if metric.Histogram.GetSampleSum() < .002 {
					t.Fatal("latency was not measured")
				}
			}
		}
	}
	if other.Status().ActiveRevision != "" || other.Status().Ready {
		t.Fatal("private instance state leaked")
	}
	w := httptest.NewRecorder()
	m.Handler().ServeHTTP(w, httptest.NewRequest("GET", "/metrics", nil))
	if w.Code != 200 || strings.Contains(w.Body.String(), "secret") || !strings.Contains(w.Body.String(), "_bucket{") {
		t.Fatal("rendered metric contract")
	}
}

func TestMetricContractRender(t *testing.T) {
	m := New()
	for _, stage := range []string{"decision", "queue", "forwarding", "delivery", "transaction", "state"} {
		m.Observe(stage, time.Now(), "error")
	}
	m.Health(false, "state_unavailable")
	families, err := m.Registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for _, f := range families {
		names[f.GetName()] = true
		if f.GetType().String() == "HISTOGRAM" {
			names[f.GetName()+"_bucket"] = true
		}
	}
	var dashboard struct {
		Panels []struct {
			Targets []struct {
				Expr string `json:"expr"`
			} `json:"targets"`
		} `json:"panels"`
	}
	raw, err := os.ReadFile("../../configs/firewall-operations-dashboard.json")
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(raw, &dashboard); err != nil {
		t.Fatal(err)
	}
	var rules struct {
		Groups []struct {
			Rules []struct {
				Expr string `yaml:"expr"`
			} `yaml:"rules"`
		} `yaml:"groups"`
	}
	raw, err = os.ReadFile("../../configs/firewall-operations-rules.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if err = yaml.Unmarshal(raw, &rules); err != nil {
		t.Fatal(err)
	}
	queries := []string{}
	for _, p := range dashboard.Panels {
		for _, q := range p.Targets {
			queries = append(queries, q.Expr)
		}
	}
	for _, g := range rules.Groups {
		for _, r := range g.Rules {
			queries = append(queries, r.Expr)
		}
	}
	re := regexp.MustCompile(`netcap_firewall_[a-z_]+`)
	p95, p99 := false, false
	for _, q := range queries {
		found := re.FindAllString(q, -1)
		if len(found) == 0 {
			t.Fatalf("no metric in query %s", q)
		}
		for _, name := range found {
			if !names[name] {
				t.Fatalf("example queries absent metric %s", name)
			}
		}
		p95 = p95 || strings.Contains(q, "histogram_quantile(0.95,")
		p99 = p99 || strings.Contains(q, "histogram_quantile(0.99,")
	}
	if !p95 || !p99 {
		t.Fatal("missing measured percentile queries")
	}
}

func TestCompositeComponentExposition(t *testing.T) {
	m := New("waf")
	state := New("state_client")
	broker := New("broker")
	m.Include(state, broker)
	m.Observe("decision", time.Now(), "allow")
	state.Observe("state", time.Now(), "error")
	broker.Observe("delivery", time.Now(), "failed")
	state.Health(false, "state_unavailable")
	broker.Health(false, "delivery_failed")
	w := httptest.NewRecorder()
	m.Handler().ServeHTTP(w, httptest.NewRequest("GET", "/metrics", nil))
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	for _, name := range []string{"waf", "state_client", "broker"} {
		if !strings.Contains(w.Body.String(), `component="`+name+`"`) {
			t.Fatal("missing component", name)
		}
	}
}
