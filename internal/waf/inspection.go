package waf

import (
	"io"
	"net/http"

	"github.com/dreadl0ck/netcap/internal/policy"
)

type inspectionEngine interface {
	request(*http.Request, io.Reader, string, bool) (inspectionTransaction, int, error)
}
type inspectionTransaction interface {
	response(*http.Response, io.Reader, bool) (int, error)
	Close() error
}

func (f *Firewall) inspectionDecision(p *policy.Compiled, phase string, status int, err error) int {
	if err != nil {
		f.stats.errors.Add(1)
		f.record(AuditRecord{Phase: phase, Verdict: "error", Status: 503})
		return 503
	}
	if status == 0 {
		return 0
	}
	if status == 400 || status == 413 {
		f.record(AuditRecord{Phase: phase, Verdict: "reject", Status: status, RuleID: "coraza-parser", Revision: p.Revision()})
		return status
	}
	monitor := p.Bundle().Mode == "monitor"
	f.record(AuditRecord{Phase: phase, Verdict: "deny", Status: status, Monitor: monitor, RuleID: "coraza", Revision: p.Revision()})
	if monitor {
		f.stats.wouldDeny.Add(1)
		return 0
	}
	f.stats.denied.Add(1)
	if status < 400 || status > 599 {
		return 403
	}
	return status
}
