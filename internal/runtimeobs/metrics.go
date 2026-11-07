// Package runtimeobs owns per-instance Prometheus registries. Label values are
// closed vocabularies; policy revisions and diagnostics belong in Status only.
package runtimeobs

import (
	"net/http"
	"slices"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const Version = 1

type Status struct {
	Version        int    `json:"version"`
	ActiveRevision string `json:"active_revision"`
	Ready          bool   `json:"ready"`
	Degraded       bool   `json:"degraded"`
	Condition      string `json:"condition"`
}

type Monitor struct {
	Registry    *prometheus.Registry
	latency     *prometheus.HistogramVec
	operations  *prometheus.CounterVec
	failures    *prometheus.CounterVec
	ready       prometheus.Gauge
	degraded    prometheus.Gauge
	condition   *prometheus.GaugeVec
	mu          sync.RWMutex
	status      Status
	children    []*Monitor
	handlerOnce sync.Once
	handler     http.Handler
}

func New(component ...string) *Monitor {
	m := &Monitor{Registry: prometheus.NewRegistry(), status: Status{Version: Version, Degraded: true, Condition: "uninitialized"}}
	name := "runtime"
	if len(component) > 0 {
		name = bounded(component[0], []string{"waf", "gateway", "network", "broker", "guard", "state_client", "policy_state", "fleet"})
	}
	register := prometheus.WrapRegistererWith(prometheus.Labels{"component": name}, m.Registry)
	m.latency = prometheus.NewHistogramVec(prometheus.HistogramOpts{Name: "netcap_firewall_operation_duration_seconds", Help: "Measured wall time at runtime boundaries, excluding unrelated stages.", Buckets: []float64{.00001, .00005, .0001, .0005, .001, .005, .01, .05, .1, .5, 1, 5, 30}}, []string{"stage"})
	m.operations = prometheus.NewCounterVec(prometheus.CounterOpts{Name: "netcap_firewall_operations_total", Help: "Completed runtime operations by bounded stage and outcome."}, []string{"stage", "outcome"})
	m.failures = prometheus.NewCounterVec(prometheus.CounterOpts{Name: "netcap_firewall_failures_total", Help: "Named runtime failures; no raw diagnostics."}, []string{"condition"})
	m.ready = prometheus.NewGauge(prometheus.GaugeOpts{Name: "netcap_firewall_ready", Help: "Local runtime readiness; does not probe upstream availability."})
	m.degraded = prometheus.NewGauge(prometheus.GaugeOpts{Name: "netcap_firewall_degraded", Help: "Last ordered runtime health result is degraded."})
	m.condition = prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "netcap_firewall_condition", Help: "Current named health condition (one hot)."}, []string{"condition"})
	register.MustRegister(m.latency, m.operations, m.failures, m.ready, m.degraded, m.condition)
	m.condition.WithLabelValues("uninitialized").Set(1)
	m.degraded.Set(1)
	return m
}

func bounded(value string, values []string) string {
	if slices.Contains(values, value) {
		return value
	}
	return "other"
}

func (m *Monitor) Observe(stage string, start time.Time, outcome string) {
	if m == nil {
		return
	}
	stage = bounded(stage, []string{"decision", "queue", "connect", "forwarding", "delivery", "transaction", "state"})
	outcome = bounded(outcome, []string{"allow", "deny", "would-deny", "ok", "error", "timeout", "overload", "dropped", "requested", "applied", "failed", "duplicate"})
	m.latency.WithLabelValues(stage).Observe(time.Since(start).Seconds())
	m.operations.WithLabelValues(stage, outcome).Inc()
}

func (m *Monitor) Health(ready bool, condition string) {
	if m == nil {
		return
	}
	condition = bounded(condition, []string{"ok", "uninitialized", "closed", "draining", "state_unavailable", "evaluation_failed", "capacity", "deadline", "audit_unavailable", "delivery_failed", "state_capacity", "state_clock", "work_budget", "cancelled"})
	m.mu.Lock()
	defer m.mu.Unlock()
	m.condition.WithLabelValues(m.status.Condition).Set(0)
	m.condition.WithLabelValues(condition).Set(1)
	m.status.Ready = ready
	m.status.Degraded = !ready
	m.status.Condition = condition
	if ready {
		m.ready.Set(1)
		m.degraded.Set(0)
	} else {
		m.ready.Set(0)
		m.degraded.Set(1)
		m.failures.WithLabelValues(condition).Inc()
	}
}

func (m *Monitor) Revision(revision string) {
	if m == nil {
		return
	}
	if len(revision) != 64 {
		return
	}
	for _, c := range revision {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return
		}
	}
	m.mu.Lock()
	m.status.ActiveRevision = revision
	m.mu.Unlock()
}

func (m *Monitor) Status() Status { m.mu.RLock(); defer m.mu.RUnlock(); return m.status }

// Include attaches distinct runtime components before serving starts.
func (m *Monitor) Include(children ...*Monitor) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.children = append(m.children, children...)
}
func (m *Monitor) Handler() http.Handler {
	m.handlerOnce.Do(func() {
		m.mu.RLock()
		gatherers := prometheus.Gatherers{m.Registry}
		for _, child := range m.children {
			if child != nil {
				gatherers = append(gatherers, child.Registry)
			}
		}
		m.mu.RUnlock()
		m.handler = promhttp.HandlerFor(gatherers, promhttp.HandlerOpts{MaxRequestsInFlight: 4, Timeout: 5 * time.Second})
	})
	return m.handler
}
