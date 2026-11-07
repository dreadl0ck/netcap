// Package firewallauth provides bootstrap-bound identities shared by firewall APIs.
package firewallauth

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"errors"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"sync"
)

type Action string

const (
	Read              Action = "read"
	Author            Action = "author"
	Evaluate          Action = "evaluate"
	Deploy            Action = "deploy"
	Rollback          Action = "rollback"
	Lease             Action = "lease"
	Audit             Action = "audit"
	Approve           Action = "approve"
	ManageCredentials Action = "manage-credentials"
	Prune             Action = "prune"
	Metrics           Action = "metrics"
)

type Scope struct {
	Tenant      string `json:"tenant"`
	App         string `json:"app"`
	Environment string `json:"environment"`
	Target      string `json:"target"`
}

// Empty grant dimensions match only empty resource dimensions. Wildcards must
// be explicit. All dimensions and the action must match the SAME grant.
type Grant struct {
	Scope   Scope    `json:"scope"`
	Actions []Action `json:"actions"`
}
type Principal struct {
	ID     string  `json:"id"`
	Grants []Grant `json:"grants"`
}

var identifier = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$`)

func validPrincipal(p Principal) bool {
	if !identifier.MatchString(p.ID) || len(p.Grants) > 128 {
		return false
	}
	for _, g := range p.Grants {
		for _, v := range []string{g.Scope.Tenant, g.Scope.App, g.Scope.Environment, g.Scope.Target} {
			if v != "" && v != "*" && !identifier.MatchString(v) {
				return false
			}
		}
		if len(g.Actions) > 11 {
			return false
		}
		for _, a := range g.Actions {
			switch a {
			case Read, Author, Evaluate, Deploy, Rollback, Lease, Audit, Approve, ManageCredentials, Prune, Metrics:
			default:
				return false
			}
		}
	}
	return true
}

func (p Principal) Allows(action Action, scope Scope) bool {
	for _, g := range p.Grants {
		match := func(a, b string) bool { return a == "*" || a == b }
		if slices.Contains(g.Actions, action) && match(g.Scope.Tenant, scope.Tenant) && match(g.Scope.App, scope.App) && match(g.Scope.Environment, scope.Environment) && match(g.Scope.Target, scope.Target) {
			return true
		}
	}
	return false
}

// BoundScope is for workload APIs whose scope is never caller supplied. Refuse
// ambiguous or wildcard bindings instead of selecting a tenant by fallback.
func (p Principal) BoundScope(action Action, environment, target string) (Scope, error) {
	var out Scope
	found := false
	for _, g := range p.Grants {
		s := Scope{Tenant: g.Scope.Tenant, App: g.Scope.App, Environment: environment, Target: target}
		if s.Tenant == "" || s.App == "" || s.Tenant == "*" || s.App == "*" || !(Principal{Grants: []Grant{g}}).Allows(action, s) {
			continue
		}
		if found && out != s {
			return Scope{}, ErrForbidden
		}
		out = s
		found = true
	}
	if !found {
		return Scope{}, ErrForbidden
	}
	return out, nil
}
func Operation(op string) Action {
	switch op {
	case "capabilities", "revision", "revisions", "diff", "status", "list":
		return Read
	case "check", "stage":
		return Author
	case "evaluate":
		return Evaluate
	case "activate", "promote", "rollout", "drain", "revoke", "resume":
		return Deploy
	case "rollback":
		return Rollback
	case "lease", "desired", "ack":
		return Lease
	case "audit", "audit_export":
		return Audit
	case "prune", "retention_preview", "audit_ack":
		return Prune
	case "metrics":
		return Metrics
	}
	return ""
}

var ErrUnauthenticated = errors.New("firewall credential rejected")
var ErrForbidden = errors.New("firewall grant required")

type principalKey struct{}

func WithPrincipal(ctx context.Context, p Principal) context.Context {
	return context.WithValue(ctx, principalKey{}, p)
}
func FromContext(ctx context.Context) (Principal, bool) {
	p, ok := ctx.Value(principalKey{}).(Principal)
	return p, ok
}
func Require(ctx context.Context, action Action, scope Scope) error {
	p, ok := FromContext(ctx)
	if !ok {
		return ErrUnauthenticated
	}
	if !p.Allows(action, scope) {
		return ErrForbidden
	}
	return nil
}

type Static struct {
	Token     string
	Principal Principal
}
type Config struct {
	Revocations Revocations
	Static      []Static
	Providers   []Provider
}

// Authority is replaced atomically by trusted configuration reload. It has no
// token-directed discovery, token issuance, or remotely writable trust settings.
type Authority struct {
	policyFingerprint string
	shared            SharedDatabase
	ledger            *sql.DB
	revocations       Revocations
	mu                sync.RWMutex
	static            []Static
	providers         []*provider
}

func New(c Config) (*Authority, error) {
	if len(c.Static) > 128 || len(c.Providers) > 16 {
		return nil, errors.New("identity configuration exceeds limit")
	}
	a := &Authority{revocations: c.Revocations}
	seen := map[[32]byte]bool{}
	for _, s := range c.Static {
		h := sha256.Sum256([]byte(s.Token))
		if len(s.Token) < 16 || !validPrincipal(s.Principal) || seen[h] {
			return nil, errors.New("invalid static identity")
		}
		seen[h] = true
		s.Principal = clone(s.Principal)
		a.static = append(a.static, s)
	}
	for _, c := range c.Providers {
		p, err := newProvider(c)
		if err != nil {
			return nil, err
		}
		a.providers = append(a.providers, p)
	}
	return a, nil
}
func clone(p Principal) Principal {
	p.Grants = slices.Clone(p.Grants)
	for i := range p.Grants {
		p.Grants[i].Actions = slices.Clone(p.Grants[i].Actions)
	}
	return p
}

// Reload revokes removed credentials and clears all JWKS caches. The caller must
// persist trusted configuration before invoking this method if restart durability is required.
func (a *Authority) Reload(c Config) error {
	if a.Shared() {
		return errors.New("shared identity policy changes require coordinated bootstrap migration")
	}
	n, err := New(c)
	if err != nil {
		return err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.static = n.static
	for _, p := range a.providers {
		p.client.CloseIdleConnections()
	}
	a.providers = n.providers
	if n.revocations != nil {
		a.revocations = n.revocations
	}
	return nil
}
func (a *Authority) Authenticate(ctx context.Context, token string) (Principal, error) {
	if token == "" || len(token) > 16384 {
		return Principal{}, ErrUnauthenticated
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	h := sha256.Sum256([]byte(token))
	if a.revocations != nil {
		revoked, err := a.revocations.Revoked(ctx, hex.EncodeToString(h[:]))
		if err != nil || revoked {
			return Principal{}, ErrUnauthenticated
		}
	}
	for _, s := range a.static {
		want := sha256.Sum256([]byte(s.Token))
		if subtle.ConstantTimeCompare(h[:], want[:]) == 1 {
			return clone(s.Principal), nil
		}
	}
	for _, p := range a.providers {
		if out, err := p.authenticate(ctx, token); err == nil {
			return out, nil
		}
	}
	return Principal{}, ErrUnauthenticated
}
func (a *Authority) Request(r *http.Request) (*http.Request, error) {
	v := r.Header.Get("Authorization")
	if !strings.HasPrefix(v, "Bearer ") {
		return nil, ErrUnauthenticated
	}
	p, err := a.Authenticate(r.Context(), strings.TrimPrefix(v, "Bearer "))
	if err != nil {
		return nil, err
	}
	return r.WithContext(WithPrincipal(r.Context(), p)), nil
}

// AllowOrigin accepts only an exact bootstrap-configured first-party origin.
// It does not emit CORS headers or accept wildcard/subdomain matches.
func AllowOrigin(r *http.Request, origin string) bool {
	if len(r.Header.Values("Origin")) > 1 {
		return false
	}
	got := r.Header.Get("Origin")
	return got == "" || origin != "" && got == origin && origin != "null" && !strings.Contains(origin, "*")
}
