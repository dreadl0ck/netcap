package waf

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"sync/atomic"
)

type counters struct{ requests, rejected, denied, wouldDeny, errors, auditDropped atomic.Uint64 }

// AuditRecord deliberately excludes URLs, addresses, headers and bodies.
type AuditRecord struct {
	Phase    string `json:"phase"`
	Verdict  string `json:"verdict"`
	Status   int    `json:"status"`
	RuleID   string `json:"rule_id,omitempty"`
	Revision string `json:"revision,omitempty"`
	Monitor  bool   `json:"monitor"`
}

func (f *Firewall) record(r AuditRecord) {
	select {
	case f.audit <- r:
	default:
		f.stats.auditDropped.Add(1)
	}
}

// WriteAudit runs separately from decisions. The caller owns cancellation and writer lifetime.
// Pass os.Stdout for JSON-line audit output; a blocked writer cannot block request processing.
func (f *Firewall) WriteAudit(ctx context.Context, w io.Writer) error {
	e := json.NewEncoder(w)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case r := <-f.audit:
			if err := e.Encode(r); err != nil {
				return err
			}
		}
	}
}

func (f *Firewall) AdminHandler() http.Handler {
	m := http.NewServeMux()
	m.HandleFunc("/livez", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200); _, _ = io.WriteString(w, "ok\n") })
	m.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		if !f.ready() {
			http.Error(w, "not ready", 503)
			return
		}
		_, _ = io.WriteString(w, "ready\n")
	})
	m.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		f.ready()
		f.Operations.Handler().ServeHTTP(w, r)
	})
	m.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(f.Operations.Status())
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { f.startServing(); m.ServeHTTP(w, r) })
}

func boolInt(v bool) int {
	if v {
		return 1
	}
	return 0
}
