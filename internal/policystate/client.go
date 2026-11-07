package policystate

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/dreadl0ck/netcap/internal/enforcer"
	"github.com/dreadl0ck/netcap/internal/firewallstate"
	"github.com/dreadl0ck/netcap/internal/policy"
)

type ClientConfig struct {
	URL, Token string
	Timeout    time.Duration
	Transport  http.RoundTripper
}
type Client struct {
	base, token string
	http        *http.Client
	ready       atomic.Int64
	mu          sync.Mutex
	operation   uint64
	closed      bool
}

func NewClient(cfg ClientConfig) (*Client, error) {
	if cfg.Timeout < 0 || cfg.Timeout > 10*time.Second {
		return nil, errors.New("invalid native policy-state timeout")
	}
	u, err := firewallstate.Endpoint(cfg.URL)
	if err != nil {
		return nil, errors.New("invalid native policy-state endpoint")
	}
	if len(cfg.Token) < 16 || len(cfg.Token) > 4096 {
		return nil, errors.New("invalid native policy-state token")
	}
	var tr *http.Transport
	if cfg.Transport == nil {
		tr = http.DefaultTransport.(*http.Transport).Clone()
	} else {
		var ok bool
		tr, ok = cfg.Transport.(*http.Transport)
		if !ok {
			return nil, errors.New("native policy state requires a verified HTTP transport")
		}
		tr = tr.Clone()
	}
	if tr.TLSClientConfig == nil {
		tr.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	} else {
		tr.TLSClientConfig = tr.TLSClientConfig.Clone()
	}
	tc := tr.TLSClientConfig
	if tr.DialTLS != nil || tr.DialTLSContext != nil {
		return nil, errors.New("native policy-state TLS dial override forbidden")
	}
	if tc.InsecureSkipVerify || tc.VerifyConnection != nil || tc.VerifyPeerCertificate != nil || tc.ServerName != "" && tc.ServerName != u.Hostname() {
		return nil, errors.New("native policy-state TLS verification override forbidden")
	}
	if tc.MinVersion < tls.VersionTLS12 {
		tc.MinVersion = tls.VersionTLS12
	}
	if tc.RootCAs != nil {
		tc.RootCAs = tc.RootCAs.Clone()
	}
	tr.Proxy = nil
	tr.MaxConnsPerHost = 8
	tr.ResponseHeaderTimeout = 5 * time.Second
	return &Client{base: strings.TrimRight(u.String(), "/"), token: cfg.Token, http: firewallstate.HTTPClient(cfg.Timeout, tr)}, nil
}

// Evaluate pins the supplied descriptor. Every attempt includes its artifact so
// expired artifact reclamation needs no mutation retry. There is exactly one HTTP
// attempt; an ambiguous failure never falls back to local state or resubmits.
func (c *Client) Evaluate(ctx context.Context, p *policy.Compiled, e policy.Event) (policy.Decision, error) {
	op, err := c.begin()
	if err != nil {
		return policy.Decision{}, err
	}
	if p == nil {
		return policy.Decision{}, errors.New("native policy descriptor required")
	}
	if err := policy.ValidateEvent(e); err != nil {
		return policy.Decision{}, err
	}
	raw, err := json.Marshal(p.Bundle())
	if err != nil {
		return policy.Decision{}, err
	}
	input := Request{Revision: p.Revision(), Bundle: raw, Event: &e}
	var d policy.Decision
	if err = c.request(ctx, http.MethodPost, EvaluatePath, input, &d, 64<<10); err != nil {
		c.finish(op, false)
		return policy.Decision{}, errors.New("native policy state unavailable; evaluation outcome may be unknown")
	}
	if err = validateDecision(p, e, d); err != nil {
		c.finish(op, false)
		return policy.Decision{}, err
	}
	c.finish(op, true)
	return d, nil
}

func (c *Client) request(ctx context.Context, method, path string, input, output any, max int64) error {
	// RequestJSON does not retry. Its result is decoded again with exact keys.
	var raw json.RawMessage
	if err := firewallstate.RequestJSON(ctx, c.http, method, c.base+path, c.token, input, &raw, max); err != nil {
		return err
	}
	return decode(raw, output)
}

func (c *Client) Probe(ctx context.Context) error {
	op, err := c.begin()
	if err != nil {
		return err
	}
	var h health
	err = c.request(ctx, http.MethodGet, HealthPath, nil, &h, 4096)
	if err != nil || h.Version != 1 || !h.Ready {
		c.finish(op, false)
		return errors.New("native policy-state probe failed")
	}
	c.finish(op, true)
	return nil
}
func (c *Client) Ready() bool {
	stamp := c.ready.Load()
	return stamp > 0 && time.Since(time.Unix(0, stamp)) <= 5*time.Second
}
func (c *Client) begin() (uint64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return 0, errors.New("native policy-state client closed")
	}
	c.operation++
	return c.operation, nil
}
func (c *Client) finish(op uint64, ready bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if op == c.operation && !c.closed {
		stamp := int64(0)
		if ready {
			stamp = time.Now().UnixNano()
		}
		c.ready.Store(stamp)
	}
}
func (c *Client) Close() {
	c.mu.Lock()
	c.closed = true
	c.operation++
	c.ready.Store(0)
	c.mu.Unlock()
	c.http.CloseIdleConnections()
}

func validateDecision(p *policy.Compiled, e policy.Event, d policy.Decision) error {
	bad := errors.New("native policy-state decision mismatch")
	b := p.Bundle()
	if d.Revision != p.Revision() || d.Monitor != (b.Mode == "monitor") || len(d.Effects) > policy.MaxEffects {
		return bad
	}
	if d.Verdict != "allow" && d.Verdict != "deny" && d.Verdict != "would-deny" {
		return bad
	}
	if d.Verdict == "would-deny" && !d.Monitor || d.Monitor && d.Verdict == "deny" || d.Verdict == "allow" && d.Status != 0 || d.Verdict != "allow" && (d.Status < 400 || d.Status > 599) {
		return bad
	}
	phase := e.Phase
	if phase == "" {
		phase = "request"
	}
	var rule *policy.Rule
	for i := range b.Rules {
		if b.Rules[i].ID == d.RuleID {
			rule = &b.Rules[i]
			break
		}
	}
	if d.RuleID != "" && (rule == nil || rule.Phase != phase || rule.Enabled != nil && !*rule.Enabled) {
		return bad
	}
	if rule != nil {
		want := rule.Action
		if want == "deny" && d.Monitor {
			want = "would-deny"
		}
		if d.Verdict != want || d.Status != rule.Status {
			return bad
		}
	}
	if d.RuleID == "" {
		want := b.Default
		if b.Defaults != nil {
			v := b.Defaults.Request
			if phase == "response" {
				v = b.Defaults.Response
			}
			if v != "" {
				want = v
			}
		}
		if want == "deny" && d.Monitor {
			want = "would-deny"
		}
		if d.Verdict != want || len(d.Effects) > 0 || want != "allow" && d.Status != 403 {
			return bad
		}
	}
	if d.Monitor && len(d.Effects) > 0 {
		return bad
	}
	if rule != nil && !d.Monitor && len(d.Effects) != len(rule.Effects) {
		return bad
	}
	for n, i := range d.Effects {
		effect := rule.Effects[n]
		ttl, _ := time.ParseDuration(effect.Duration)
		source := e.ClientIP
		if effect.Target == "source" {
			source = e.Network.SrcIP
		}
		var flow enforcer.Flow
		if effect.Kind == string(enforcer.DropFlow) || effect.Kind == string(enforcer.RejectFlow) {
			var err error
			flow, err = policy.EventFlow(e)
			if err != nil {
				return bad
			}
		}
		if i.Revision != d.Revision || i.RuleID != d.RuleID || i.Kind != effect.Kind || i.Profile != effect.Profile || i.Flow != flow || i.Target != effect.Target || i.Scope != effect.Scope || i.Source != source || i.TTL != ttl || i.ID != policy.IntentID(i) || i.IssuedAt.IsZero() || !i.ExpiresAt.Equal(i.IssuedAt.Add(ttl)) {
			return bad
		}
	}
	return nil
}
