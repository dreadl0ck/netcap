package firewallauth

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// Provider binds an issuer's authenticated subjects to locally trusted grants.
// JWKSURL is pinned by the operator, never read from a token or discovery reply.
type Provider struct {
	Issuer      string               `json:"issuer"`
	Audience    string               `json:"audience"`
	JWKSURL     string               `json:"jwksURL"`
	Subjects    map[string]Principal `json:"subjects"`
	TTL         time.Duration        `json:"ttl"`
	MaxLifetime time.Duration        `json:"maxLifetime"`
	ClockSkew   time.Duration        `json:"clockSkew"`
	RevokedIDs  []string             `json:"revokedIDs"`
}
type provider struct {
	cfg                Provider
	mu                 sync.Mutex
	keys               jose.JSONWebKeySet
	expires, nextFetch time.Time
	client             *http.Client
}

func newProvider(c Provider) (*provider, error) {
	u, err := url.Parse(c.JWKSURL)
	if err != nil || u.Host == "" || u.User != nil || u.Fragment != "" || u.RawQuery != "" {
		return nil, errors.New("invalid trusted JWKS endpoint")
	}
	ip := net.ParseIP(u.Hostname())
	if u.Scheme != "https" && !(u.Scheme == "http" && ip != nil && ip.IsLoopback()) {
		return nil, errors.New("JWKS requires HTTPS (literal loopback HTTP allowed for tests)")
	}
	if c.Issuer == "" || c.Audience == "" || len(c.Subjects) > 1024 {
		return nil, errors.New("issuer, audience and bounded subject bindings required")
	}
	if len(c.RevokedIDs) > 4096 {
		return nil, errors.New("revoked JWT ID limit exceeded")
	}
	c.RevokedIDs = append([]string(nil), c.RevokedIDs...)
	if c.TTL == 0 {
		c.TTL = time.Minute
	}
	if c.MaxLifetime == 0 {
		c.MaxLifetime = 15 * time.Minute
	}
	if c.TTL < time.Second || c.TTL > 5*time.Minute || c.MaxLifetime < time.Second || c.MaxLifetime > time.Hour || c.ClockSkew < 0 || c.ClockSkew > time.Minute {
		return nil, errors.New("invalid OIDC time limits")
	}
	bindings := make(map[string]Principal, len(c.Subjects))
	for sub, p := range c.Subjects {
		if sub == "" || !validPrincipal(p) {
			return nil, errors.New("invalid subject binding")
		}
		bindings[sub] = clone(p)
	}
	c.Subjects = bindings
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.MaxConnsPerHost = 2
	t.ResponseHeaderTimeout = 2 * time.Second
	return &provider{cfg: c, client: &http.Client{Transport: t, Timeout: 3 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("JWKS redirect refused") }}}, nil
}
func (p *provider) key(ctx context.Context, kid, alg string) (any, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := time.Now()
	find := func() (any, error) {
		var found any
		for _, k := range p.keys.Keys {
			if k.KeyID == kid && k.Algorithm == alg && (k.Use == "sig" || k.Use == "") && k.IsPublic() && k.Valid() {
				if found != nil {
					return nil, ErrUnauthenticated
				}
				found = k.Key
			}
		}
		if found == nil {
			return nil, ErrUnauthenticated
		}
		return found, nil
	}
	if now.Before(p.expires) {
		if k, err := find(); err == nil {
			return k, nil
		}
	}
	// A single per-provider cooldown also bounds attacker-chosen unknown kids;
	// no per-kid entries exist, so memory cannot grow with token cardinality.
	if now.Before(p.nextFetch) {
		return nil, ErrUnauthenticated
	}
	p.nextFetch = now.Add(time.Second)
	r, err := http.NewRequestWithContext(ctx, http.MethodGet, p.cfg.JWKSURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := p.client.Do(r)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, ErrUnauthenticated
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, (256<<10)+1))
	if err != nil || len(raw) > 256<<10 {
		return nil, ErrUnauthenticated
	}
	var keys jose.JSONWebKeySet
	if json.Unmarshal(raw, &keys) != nil || len(keys.Keys) == 0 || len(keys.Keys) > 32 {
		return nil, ErrUnauthenticated
	}
	p.keys = keys
	p.expires = now.Add(p.cfg.TTL)
	return find()
}
func (p *provider) authenticate(ctx context.Context, raw string) (Principal, error) {
	t, err := jwt.ParseSigned(raw, []jose.SignatureAlgorithm{jose.RS256, jose.ES256, jose.EdDSA})
	if err != nil || len(t.Headers) != 1 {
		return Principal{}, ErrUnauthenticated
	}
	h := t.Headers[0]
	if h.KeyID == "" || len(h.KeyID) > 128 {
		return Principal{}, ErrUnauthenticated
	}
	k, err := p.key(ctx, h.KeyID, h.Algorithm)
	if err != nil {
		return Principal{}, err
	}
	var c jwt.Claims
	if t.Claims(k, &c) != nil {
		return Principal{}, ErrUnauthenticated
	}
	for _, id := range p.cfg.RevokedIDs {
		if c.ID == id {
			return Principal{}, ErrUnauthenticated
		}
	}
	now := time.Now()
	if c.Expiry == nil || c.IssuedAt == nil || c.Subject == "" || c.Expiry.Time().Sub(c.IssuedAt.Time()) > p.cfg.MaxLifetime || !c.Expiry.Time().After(c.IssuedAt.Time()) {
		return Principal{}, ErrUnauthenticated
	}
	if c.ValidateWithLeeway(jwt.Expected{Issuer: p.cfg.Issuer, AnyAudience: jwt.Audience{p.cfg.Audience}, Time: now}, p.cfg.ClockSkew) != nil {
		return Principal{}, ErrUnauthenticated
	}
	out, ok := p.cfg.Subjects[c.Subject]
	if !ok {
		return Principal{}, ErrUnauthenticated
	}
	return clone(out), nil
}
