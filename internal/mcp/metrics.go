/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 */

package mcp

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Metrics aggregates the Prometheus collectors the MCP server publishes.
// Each Server holds its own *Metrics so multiple MCP instances in one
// process (e.g. test cases) don't fight over a shared global registry.
//
// Exposed on the operator's choice of mount point — by default we attach
// promhttp at /mcp/metrics. The mount only happens when an admin token
// is set, mirroring the auth posture of the MCP endpoint itself: nobody
// without the token can scrape the metrics.
type Metrics struct {
	reg      *prometheus.Registry
	calls    *prometheus.CounterVec
	errors   *prometheus.CounterVec
	duration *prometheus.HistogramVec
	resBytes *prometheus.HistogramVec
	carve    prometheus.Gauge
	carveTot prometheus.Gauge
	cveHits  prometheus.Counter
	cveMiss  prometheus.Counter
}

// NewMetrics constructs a fresh registry plus the canonical collector
// set. Labels are kept short (tool name, status) so cardinality stays
// bounded by the tool catalogue size.
func NewMetrics() *Metrics {
	reg := prometheus.NewRegistry()
	m := &Metrics{
		reg: reg,
		calls: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "netcap_mcp",
			Name:      "tool_calls_total",
			Help:      "Total number of MCP tool invocations.",
		}, []string{"tool", "status"}),
		errors: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "netcap_mcp",
			Name:      "tool_errors_total",
			Help:      "Total number of MCP tool invocations that returned an error result (IsError=true) or a transport failure.",
		}, []string{"tool"}),
		duration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: "netcap_mcp",
			Name:      "tool_duration_seconds",
			Help:      "MCP tool-call latency, including upstream HTTP roundtrip.",
			Buckets:   prometheus.ExponentialBuckets(0.001, 2, 14), // 1ms..8s
		}, []string{"tool"}),
		resBytes: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: "netcap_mcp",
			Name:      "tool_response_bytes",
			Help:      "Size of MCP tool-call response text content (bytes).",
			Buckets:   []float64{64, 256, 1024, 4096, 16384, 65536, 262144, 1048576},
		}, []string{"tool"}),
		carve: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: "netcap_mcp",
			Name:      "carve_entries",
			Help:      "Number of carved sub-PCAPs currently held in CarveStore.",
		}),
		carveTot: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: "netcap_mcp",
			Name:      "carve_bytes",
			Help:      "Total bytes held in CarveStore across all entries.",
		}),
		cveHits: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: "netcap_mcp",
			Name:      "cve_cache_hits_total",
			Help:      "Number of lookup_cve calls served from the in-process cache.",
		}),
		cveMiss: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: "netcap_mcp",
			Name:      "cve_cache_misses_total",
			Help:      "Number of lookup_cve calls that performed a fresh NVD fetch.",
		}),
	}
	reg.MustRegister(m.calls, m.errors, m.duration, m.resBytes, m.carve, m.carveTot, m.cveHits, m.cveMiss)
	return m
}

// Handler returns an http.Handler exposing the registered collectors in
// Prometheus text format.
func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.reg, promhttp.HandlerOpts{})
}

// observeToolCall records one tool invocation. status is "ok",
// "error_result" (handler returned IsError=true), or "error" (Go error).
func (m *Metrics) observeToolCall(tool, status string, durationSec float64, responseBytes int) {
	m.calls.WithLabelValues(tool, status).Inc()
	m.duration.WithLabelValues(tool).Observe(durationSec)
	m.resBytes.WithLabelValues(tool).Observe(float64(responseBytes))
	if status != "ok" {
		m.errors.WithLabelValues(tool).Inc()
	}
}
