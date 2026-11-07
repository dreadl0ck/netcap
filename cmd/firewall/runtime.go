package firewall

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"sync/atomic"
	"time"

	"github.com/dreadl0ck/netcap/internal/firewallfleet"
	"github.com/dreadl0ck/netcap/internal/firewallstate"
	"github.com/dreadl0ck/netcap/internal/firewalltransport"
	"github.com/dreadl0ck/netcap/internal/policy"
	"github.com/dreadl0ck/netcap/internal/policystate"
	"github.com/dreadl0ck/netcap/internal/responseactions"
	"github.com/dreadl0ck/netcap/internal/waf"
	"github.com/urfave/cli/v3"
)

func strictFile(path string, dst any) error {
	raw, err := readBounded(path, 1<<20)
	if err != nil {
		return err
	}
	if err = firewallstate.Decode(raw, dst); err != nil {
		return fmt.Errorf("invalid JSON config %s: %w", path, err)
	}
	return nil
}

var envName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

func envToken(name string) (string, error) {
	if !envName.MatchString(name) {
		return "", errors.New("valid tokenEnv required")
	}
	token := os.Getenv(name)
	if len(token) < 16 || len(token) > 4096 {
		return "", errors.New("missing or invalid token environment value")
	}
	return token, nil
}

func clientTLS(ca, cert, key string) (*tls.Config, error) {
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if ca != "" {
		raw, err := readBounded(ca, 1<<20)
		if err != nil {
			return nil, err
		}
		cfg.RootCAs = x509.NewCertPool()
		if !cfg.RootCAs.AppendCertsFromPEM(raw) {
			return nil, errors.New("invalid CA PEM")
		}
	}
	if (cert == "") != (key == "") {
		return nil, errors.New("client certificate and key must be paired")
	}
	if cert != "" {
		pair, err := tls.LoadX509KeyPair(cert, key)
		if err != nil {
			return nil, err
		}
		cfg.Certificates = []tls.Certificate{pair}
	}
	return cfg, nil
}

type effectsFile struct {
	Scopes      map[string]responseactions.Scope `json:"scopes"`
	QueueSize   int                              `json:"queueSize"`
	MaxPending  int                              `json:"maxPending"`
	MaxReceipts int                              `json:"maxReceipts"`
	Retention   time.Duration                    `json:"retention"`
	CA          string                           `json:"ca"`
	Cert        string                           `json:"cert"`
	Key         string                           `json:"key"`
}

func effectsBroker(path string) (*responseactions.Broker, error) {
	if path == "" {
		return nil, nil
	}
	var f effectsFile
	if err := strictFile(path, &f); err != nil {
		return nil, err
	}
	tc, err := clientTLS(f.CA, f.Cert, f.Key)
	if err != nil {
		return nil, err
	}
	return responseactions.New(responseactions.Config{Scopes: f.Scopes, QueueSize: f.QueueSize, MaxPending: f.MaxPending, MaxReceipts: f.MaxReceipts, Retention: f.Retention, TLSConfig: tc})
}

func loadPolicyOptions(path string, effects bool) (*policy.Compiled, error) {
	raw, err := readBounded(path, policy.MaxBundleBytes)
	if err != nil {
		return nil, err
	}
	b, err := policy.Parse(raw)
	if err != nil {
		return nil, err
	}
	return policy.CompileWithOptions(b, policy.CompileOptions{AllowEffects: effects})
}

type rateFile struct {
	URL            string        `json:"url"`
	TokenEnv       string        `json:"tokenEnv"`
	Window         time.Duration `json:"window"`
	Limit          int64         `json:"limit"`
	GroupBy        string        `json:"group_by"`
	ID             string        `json:"id"`
	CA             string        `json:"ca"`
	Cert           string        `json:"cert"`
	Key            string        `json:"key"`
	RequestTimeout time.Duration `json:"requestTimeout"`
	Unit           string        `json:"unit"`
}

type runtimeEvaluator struct {
	ctx          context.Context
	p            atomic.Pointer[policy.Compiled]
	guard        *firewallstate.Guard
	broker       *responseactions.Broker
	stateClient  *firewallstate.Client
	nativeState  *policystate.Client
	fleetUnready atomic.Bool
	agentStatus  atomic.Pointer[firewallfleet.AgentStatus]
	probeCancel  context.CancelFunc
	probeDone    chan struct{}
}

func newEvaluator(ctx context.Context, c *cli.Command, path string) (*runtimeEvaluator, error) {
	b, err := effectsBroker(c.String("effects-config"))
	if err != nil {
		return nil, err
	}
	r := &runtimeEvaluator{ctx: ctx, broker: b}
	fail := func(err error) (*runtimeEvaluator, error) { r.Close(); return nil, err }
	p, err := loadPolicyOptions(path, b != nil)
	if err != nil {
		return fail(err)
	}
	r.p.Store(p)
	if path := c.String("policy-state-config"); path != "" {
		if c.String("shared-rate-config") != "" {
			return fail(errors.New("policy-state-config and shared-rate-config are mutually exclusive"))
		}
		r.nativeState, err = nativeStateClient(path)
		if err != nil {
			return fail(err)
		}
	}
	if path := c.String("shared-rate-config"); path != "" {
		var f rateFile
		if err = strictFile(path, &f); err != nil {
			return fail(err)
		}
		token, e := envToken(f.TokenEnv)
		if e != nil {
			return fail(e)
		}
		tc, e := clientTLS(f.CA, f.Cert, f.Key)
		if e != nil {
			return fail(e)
		}
		tr := &http.Transport{TLSClientConfig: tc, MaxConnsPerHost: 16, MaxIdleConnsPerHost: 2, IdleConnTimeout: time.Minute, ResponseHeaderTimeout: 5 * time.Second}
		r.stateClient, err = firewallstate.NewClient(firewallstate.ClientConfig{URL: f.URL, Token: token, Timeout: f.RequestTimeout, Transport: tr})
		if err != nil {
			tr.CloseIdleConnections()
			return fail(err)
		}
		r.guard, err = firewallstate.NewGuardWithStore(firewallstate.GuardConfig{URL: f.URL, Token: token, Window: f.Window, Limit: f.Limit, GroupBy: f.GroupBy, ID: f.ID, Unit: f.Unit}, r.stateClient)
		if err != nil {
			return fail(err)
		}
	}
	return r, nil
}

func (r *runtimeEvaluator) Policy() *policy.Compiled     { return r.p.Load() }
func (r *runtimeEvaluator) SetPolicy(p *policy.Compiled) { r.p.Store(p) }
func (r *runtimeEvaluator) Close() {
	if r.probeCancel != nil {
		r.probeCancel()
		<-r.probeDone
	}
	if r.stateClient != nil {
		r.stateClient.Close()
	}
	if r.nativeState != nil {
		r.nativeState.Close()
	}
	if r.broker != nil {
		_ = r.broker.Close()
	}
}

func (r *runtimeEvaluator) Ready() bool {
	if r.fleetUnready.Load() || r.ctx.Err() != nil {
		return false
	}
	if r.guard != nil {
		ready, _ := r.guard.Ready()
		return ready
	}
	if r.nativeState != nil {
		return r.nativeState.Ready()
	}
	return true
}

func (r *runtimeEvaluator) startProbes(ctx context.Context) {
	if r.guard == nil && r.nativeState == nil {
		return
	}
	ctx, r.probeCancel = context.WithCancel(ctx)
	r.probeDone = make(chan struct{})
	go func() {
		defer close(r.probeDone)
		probe := func() {
			bounded, cancel := context.WithTimeout(ctx, 2*time.Second)
			defer cancel()
			if r.guard != nil {
				_ = r.guard.Probe(bounded)
			}
			if r.nativeState != nil {
				_ = r.nativeState.Probe(bounded)
			}
		}
		probe()
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				probe()
			}
		}
	}()
}

type evaluateFunc func(policy.Event) (policy.Decision, error)

func (f evaluateFunc) Evaluate(e policy.Event) (policy.Decision, error) { return f(e) }

func (r *runtimeEvaluator) evaluate(p *policy.Compiled, e policy.Event) (policy.Decision, error) {
	return r.evaluateContext(r.ctx, p, e)
}
func (r *runtimeEvaluator) evaluateContext(ctx context.Context, p *policy.Compiled, e policy.Event) (policy.Decision, error) {
	if p == nil {
		return policy.Decision{Verdict: "deny", Status: 503}, errors.New("policy target unready")
	}
	if r.fleetUnready.Load() {
		return policy.Decision{Verdict: "deny", Status: 503, Revision: p.Revision()}, nil
	}
	base := evaluateFunc(func(e policy.Event) (policy.Decision, error) {
		if r.nativeState != nil {
			d, err := r.nativeState.Evaluate(ctx, p, e)
			if err != nil {
				return policy.Decision{Verdict: "deny", Status: 503, Revision: p.Revision()}, nil
			}
			return d, nil
		}
		if r.guard != nil {
			return r.guard.Evaluate(ctx, p, e)
		}
		return p.Evaluate(e)
	})
	wrapped := responseactions.Evaluator{Policy: base, Broker: r.broker, Source: func(e policy.Event, target string) (string, bool) {
		// These events are constructed only by socket/validated-proxy/packet adapters.
		if target == "client" {
			return e.ClientIP, e.ClientIP != ""
		}
		if target == "source" {
			return e.Network.SrcIP, e.Network.SrcIP != ""
		}
		return "", false
	}}
	return wrapped.Evaluate(e)
}
func (r *runtimeEvaluator) Evaluate(e policy.Event) (policy.Decision, error) {
	return r.evaluate(r.Policy(), e)
}

func validateServeOptions(c *cli.Command, cfg waf.Config) error {
	if c.Bool("managed") && c.String("fleet-agent-config") != "" {
		return errors.New("fleet-agent-config and managed are mutually exclusive")
	}
	if path := c.String("fleet-agent-config"); path != "" {
		_, closeTransport, err := agentConfig(path, c.String("effects-config") != "")
		closeTransport()
		if err != nil {
			return err
		}
	}
	if c.String("http3-listen") != "" {
		if !firewalltransport.HTTP3Available {
			return errors.New("HTTP/3 unavailable: rebuild with -tags http3")
		}
		if cfg.TLSCert == "" || cfg.TLSKey == "" {
			return errors.New("HTTP/3 requires runtime TLS certificate and key")
		}
	}
	return nil
}

func gatewayFlags() []cli.Flag {
	return []cli.Flag{
		&cli.StringFlag{Name: "protocol", Required: true, Usage: "modbus | dns | dns-tcp | dns-tls | redis | postgres | smtp | mysql | dnp3"},
		&cli.StringFlag{Name: "listen", Required: true}, &cli.StringFlag{Name: "upstream", Required: true}, &cli.StringFlag{Name: "policy", Required: true},
		&cli.StringSliceFlag{Name: "allow-client", Usage: "source CIDRs; default loopback only"},
		&cli.StringFlag{Name: "effects-config"}, &cli.StringFlag{Name: "shared-rate-config"},
		&cli.StringFlag{Name: "policy-state-config"},
		&cli.StringFlag{Name: "fleet-agent-config"},
		&cli.StringFlag{Name: "tls-cert"}, &cli.StringFlag{Name: "tls-key"}, &cli.StringFlag{Name: "client-ca"},
		&cli.BoolFlag{Name: "upstream-tls"}, &cli.StringFlag{Name: "upstream-server-name"}, &cli.StringFlag{Name: "upstream-ca"}, &cli.StringFlag{Name: "upstream-cert"}, &cli.StringFlag{Name: "upstream-key"},
		&cli.IntFlag{Name: "max-connections", Value: 64}, &cli.IntFlag{Name: "max-message-bytes", Value: 1 << 20}, &cli.IntFlag{Name: "max-session-messages", Value: 10000}, &cli.IntFlag{Name: "max-state-entries", Value: 128}, &cli.IntFlag{Name: "max-dns-response-bytes"},
		&cli.DurationFlag{Name: "idle-timeout", Value: 30 * time.Second}, &cli.DurationFlag{Name: "io-timeout", Value: 5 * time.Second}, &cli.DurationFlag{Name: "session-timeout", Value: 5 * time.Minute},
	}
}
