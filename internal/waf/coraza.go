//go:build coraza

package waf

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"

	coreruleset "github.com/corazawaf/coraza-coreruleset/v4"
	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/experimental"
	"github.com/corazawaf/coraza/v3/types"
)

// The connector requires coraza/v3 v3.8.1 and coraza-coreruleset/v4 v4.25.0.
type corazaEngine struct{ waf, validator coraza.WAF }
type corazaTransaction struct{ types.Transaction }

func newInspectionEngine(c Config) (inspectionEngine, error) {
	if !c.CorazaCRS {
		return nil, nil
	}
	ids := map[int]bool{}
	w, err := coraza.NewWAF(experimental.WAFConfigWithRuleObserver(coraza.NewWAFConfig().WithRootFS(coreruleset.FS), func(r types.RuleMetadata) {
		for _, tag := range r.Tags() {
			if strings.HasPrefix(tag, "attack-") {
				ids[r.ID()] = true
			}
		}
	}).WithDirectives(corazaDirectives(c)))
	if err != nil {
		return nil, err
	}
	if c.CRSProfile != nil {
		for _, e := range c.CRSProfile.Exclusions {
			if !ids[e.RuleID] {
				return nil, fmt.Errorf("unknown CRS rule %d", e.RuleID)
			}
		}
	}
	validator, err := coraza.NewWAF(coraza.NewWAFConfig().WithRootFS(coreruleset.FS).WithDirectives(strings.Replace(corazaDirectives(c), "Include @owasp_crs/*.conf", "", 1)))
	if err != nil {
		return nil, err
	}
	return &corazaEngine{waf: w, validator: validator}, nil
}

func corazaDirectives(c Config) string {
	// Disable Coraza's file audit/debug sinks: the outer proxy owns redacted audit.
	// Coraza shares spool readers and spills its own request representation at 64 KiB.
	return fmt.Sprintf(`
Include @coraza.conf-recommended
Include @crs-setup.conf.example
SecRuleEngine On
SecAuditEngine Off
SecDebugLogLevel 0
SecRequestBodyAccess On
SecRequestBodyJsonDepthLimit 64
SecArgumentsLimit 1000
SecRequestBodyLimit %d
SecRequestBodyNoFilesLimit %d
SecRequestBodyInMemoryLimit %d
SecRequestBodyLimitAction Reject
SecResponseBodyAccess %s
SecResponseBodyLimit %d
SecResponseBodyLimitAction Reject
SecRule ARGUMENTS_LIMIT_REACHED "@eq 1" "id:10000001,phase:1,deny,status:413,nolog"
SecRule ARGUMENTS_LIMIT_REACHED "@eq 1" "id:10000002,phase:2,deny,status:413,nolog"
%s
Include @owasp_crs/*.conf
`, c.MaxBodyBytes+1, c.MaxBodyBytes+1, min(c.MaxBodyBytes+1, bodyMemoryBytes), map[bool]string{true: "On", false: "Off"}[c.InspectResponse], c.MaxResponseBytes+1, profileDirectives(c.CRSProfile))
}

func profileDirectives(p *CRSProfile) string {
	if p == nil {
		return ""
	}
	s := fmt.Sprintf(`SecAction "id:10000100,phase:1,pass,nolog,setvar:tx.blocking_paranoia_level=%d,setvar:tx.detection_paranoia_level=%d,setvar:tx.inbound_anomaly_score_threshold=%d,setvar:tx.outbound_anomaly_score_threshold=%d"`, p.ParanoiaLevel, p.ParanoiaLevel, p.InboundThreshold, p.OutboundThreshold)
	for i, e := range p.Exclusions {
		ctl := fmt.Sprintf("ruleRemoveById=%d", e.RuleID)
		if e.Parameter != "" {
			ctl = fmt.Sprintf("ruleRemoveTargetById=%d;ARGS:%s", e.RuleID, e.Parameter)
		}
		s += fmt.Sprintf("\nSecRule TIME_EPOCH \"@lt %d\" \"id:%d,phase:1,pass,nolog,ctl:%s\"", e.ExpiresAt.Unix(), 10000200+i, ctl)
	}
	return s
}

func interruptionStatus(i *types.Interruption) int {
	if i == nil {
		return 0
	}
	if i.Status < 400 || i.Status > 599 {
		return 403
	}
	return i.Status
}

func (e *corazaEngine) request(r *http.Request, body io.Reader, client string, monitor bool) (inspectionTransaction, int, error) {
	tx := &corazaTransaction{e.waf.NewTransaction()}
	port := 0
	if _, p, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		port, _ = strconv.Atoi(p)
	}
	tx.ProcessConnection(client, port, "", 0)
	host := r.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	tx.SetServerName(host)
	tx.ProcessURI(r.URL.RequestURI(), r.Method, r.Proto)
	tx.AddRequestHeader("Host", r.Host)
	tx.AddRequestHeader("Content-Length", strconv.FormatInt(r.ContentLength, 10))
	for k, vs := range r.Header {
		for _, v := range vs {
			tx.AddRequestHeader(k, v)
		}
	}
	if i := tx.ProcessRequestHeaders(); i != nil {
		// On stops at the first disruption. In monitor mode a parser-only
		// transaction must still reject structural errors hidden by a phase-1 deny.
		if monitor && i.Status != 400 && i.Status != 413 {
			if e.validator == nil {
				return tx, 0, errors.New("missing Coraza structural validator")
			}
			validation, status, err := (&corazaEngine{waf: e.validator}).request(r, body, client, false)
			if validation != nil {
				_ = validation.Close()
			}
			if err != nil || status != 0 {
				return tx, status, err
			}
		}
		return tx, interruptionStatus(i), nil
	}
	i, _, err := tx.ReadRequestBodyFrom(body)
	if err != nil || i != nil {
		return tx, interruptionStatus(i), err
	}
	i, err = tx.ProcessRequestBody()
	return tx, interruptionStatus(i), err
}

func (tx *corazaTransaction) response(r *http.Response, body io.Reader, inspect bool) (int, error) {
	if tx.IsInterrupted() {
		return 0, nil
	}
	for k, vs := range r.Header {
		for _, v := range vs {
			tx.AddResponseHeader(k, v)
		}
	}
	if i := tx.ProcessResponseHeaders(r.StatusCode, r.Proto); i != nil {
		return interruptionStatus(i), nil
	}
	if !inspect {
		return 0, nil
	}
	i, _, err := tx.ReadResponseBodyFrom(body)
	if err != nil || i != nil {
		return interruptionStatus(i), err
	}
	i, err = tx.ProcessResponseBody()
	return interruptionStatus(i), err
}
