package waf

import "github.com/prometheus/client_golang/prometheus"

func (f *Firewall) registerLegacyMetrics() {
	for name, value := range map[string]func() float64{
		"waf_requests_total":          func() float64 { return float64(f.stats.requests.Load()) },
		"waf_rejected_total":          func() float64 { return float64(f.stats.rejected.Load()) },
		"waf_denied_total":            func() float64 { return float64(f.stats.denied.Load()) },
		"waf_would_deny_total":        func() float64 { return float64(f.stats.wouldDeny.Load()) },
		"waf_evaluation_errors_total": func() float64 { return float64(f.stats.errors.Load()) },
		"waf_audit_dropped_total":     func() float64 { return float64(f.stats.auditDropped.Load()) },
	} {
		f.Operations.Registry.MustRegister(prometheus.NewCounterFunc(prometheus.CounterOpts{Name: name, Help: "WAF runtime counter."}, value))
	}
	f.Operations.Registry.MustRegister(prometheus.NewGaugeFunc(prometheus.GaugeOpts{Name: "waf_active", Help: "Active request slots."}, func() float64 { return float64(len(f.slots)) }))
	f.Operations.Registry.MustRegister(prometheus.NewGaugeFunc(prometheus.GaugeOpts{Name: "waf_response_body_inspection", Help: "Response body inspection enabled."}, func() float64 { return float64(boolInt(f.cfg.InspectResponse)) }))
}
