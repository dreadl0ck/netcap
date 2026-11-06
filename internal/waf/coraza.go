//go:build coraza

package waf

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"

	coreruleset "github.com/corazawaf/coraza-coreruleset/v4"
	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/types"
)

// The connector requires coraza/v3 v3.8.1 and coraza-coreruleset/v4 v4.25.0.
type corazaEngine struct{ waf, validator coraza.WAF }
type corazaTransaction struct{ types.Transaction }

func newInspectionEngine(c Config) (inspectionEngine, error) {
	if !c.CorazaCRS {
		return nil, nil
	}
	w, err := coraza.NewWAF(coraza.NewWAFConfig().WithRootFS(coreruleset.FS).WithDirectives(corazaDirectives(c)))
	if err != nil {
		return nil, err
	}
	validator, err := coraza.NewWAF(coraza.NewWAFConfig().WithRootFS(coreruleset.FS).WithDirectives(strings.Replace(corazaDirectives(c), "Include @owasp_crs/*.conf", "", 1)))
	if err != nil {
		return nil, err
	}
	return &corazaEngine{waf: w, validator: validator}, nil
}

func corazaDirectives(c Config) string {
	// Disable Coraza's file audit/debug sinks: the outer proxy owns redacted audit.
	// Keep all Coraza body buffers in memory within the outer proxy's admission cap.
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
SecRequestBodyInMemoryLimit %d
SecRequestBodyLimitAction Reject
SecResponseBodyAccess %s
SecResponseBodyLimit %d
SecResponseBodyLimitAction Reject
SecRule ARGUMENTS_LIMIT_REACHED "@eq 1" "id:10000001,phase:1,deny,status:413,nolog"
SecRule ARGUMENTS_LIMIT_REACHED "@eq 1" "id:10000002,phase:2,deny,status:413,nolog"
Include @owasp_crs/*.conf
`, c.MaxBodyBytes+1, c.MaxBodyBytes+1, map[bool]string{true: "On", false: "Off"}[c.InspectResponse], c.MaxResponseBytes+1)
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

func (e *corazaEngine) request(r *http.Request, body []byte, client string, monitor bool) (inspectionTransaction, int, error) {
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
	tx.AddRequestHeader("Content-Length", strconv.Itoa(len(body)))
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
	i, n, err := tx.WriteRequestBody(body)
	if err != nil || i != nil {
		return tx, interruptionStatus(i), err
	}
	if n != len(body) {
		return tx, 0, errors.New("incomplete Coraza request inspection")
	}
	i, err = tx.ProcessRequestBody()
	return tx, interruptionStatus(i), err
}

func (tx *corazaTransaction) response(r *http.Response, body []byte, inspect bool) (int, error) {
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
	i, n, err := tx.WriteResponseBody(body)
	if err != nil || i != nil {
		return interruptionStatus(i), err
	}
	if n != len(body) {
		return 0, errors.New("incomplete Coraza response inspection")
	}
	i, err = tx.ProcessResponseBody()
	return interruptionStatus(i), err
}
