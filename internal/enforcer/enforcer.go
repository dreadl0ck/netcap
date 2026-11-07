// Package enforcer provides opt-in, finite source-address blocks for one immutable
// network scope. Handler can be mounted by an existing HTTP server; this package
// never starts a listener. Backends are trusted executors, not authorization boundaries.
package enforcer

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"regexp"
	"sort"
	"sync"
	"time"

	"github.com/dreadl0ck/netcap/internal/firewallauth"
)

const (
	HardMaxTTL    = 15 * time.Minute
	HardMaxLeases = 1000
)

var (
	ErrConflict = errors.New("lease ID or packet selector already in use")
	ErrLimit    = errors.New("lease limit reached")
	identifier  = regexp.MustCompile(`^[a-zA-Z0-9_][a-zA-Z0-9_-]{0,47}$`)
	tableName   = regexp.MustCompile(`^netcap_firewall_[a-zA-Z0-9_]{1,40}$`)
)

// Scope applies only to packets entering Interface, destined for DestinationCIDR
// and Port using Protocol. Hook must explicitly be "input" or "forward".
// There is no output hook, interface wildcard, all-ports or all-protocols mode.
type Scope struct {
	Hook            string `json:"hook"`
	Interface       string `json:"interface"`
	DestinationCIDR string `json:"destination_cidr"`
	Protocol        string `json:"protocol"`
	Port            uint16 `json:"port"`
}

type Config struct {
	Approvals *firewallauth.Approvals
	Auth      *firewallauth.Authority
	AuthScope firewallauth.Scope
	Origin    string
	Token     string
	Table     string
	// Namespace is an existing named Linux netns under /run/netns. It is required
	// by NewNFTBackend; enforcer never creates a namespace or targets the default one.
	Namespace      string
	Scope          Scope
	ProtectedCIDRs []string
	MaxLeases      int
	MaxTTL         time.Duration
	DryRun         bool
	// StateFile is an optional private desired-state snapshot. Its parent must
	// exist. A sibling .lock prevents concurrent controllers using the same file.
	StateFile         string
	Profiles          map[string]Profile
	ProtectedServices []Service
}

type Lease struct {
	Action Action `json:"action,omitempty"`
	ID     string `json:"id"`
	Source string `json:"source"`
	Scope  Scope  `json:"scope"`
	// TTLSeconds is the ceiling of the admission-time lifetime in seconds.
	// ExpiresAt is authoritative; subsecond leases do not receive a fresh second.
	TTLSeconds int64     `json:"ttl_seconds"`
	ExpiresAt  time.Time `json:"expires_at"`
}

// Backend operations must be idempotent. Apply must never extend ExpiresAt;
// Delete must remove only the exact lease. List returns only owned leases.
// Implementations must enforce expiry independently of Controller.Reconcile.
type Backend interface {
	Apply(context.Context, Lease) error
	Delete(context.Context, Lease) error
	List(context.Context) ([]Lease, error)
}

type Controller struct {
	mu          sync.Mutex
	config      Config
	protected   []netip.Prefix
	backend     Backend
	leases      map[string]Lease
	unlock      func() error
	closed      bool
	initialized bool
}

func normalize(c Config) (Config, []netip.Prefix, error) {
	if c.Approvals != nil && c.Auth == nil {
		return c, nil, errors.New("approval protection requires identity authority")
	}
	if c.Auth == nil && (len(c.Token) < 32 || len(c.Token) > 4096) {
		return c, nil, errors.New("bearer token must contain 32..4096 bytes")
	}
	if c.Table == "" {
		c.Table = "netcap_firewall_leases"
	}
	if !tableName.MatchString(c.Table) {
		return c, nil, errors.New("table must match netcap_firewall_[A-Za-z0-9_]{1,40}")
	}
	if c.MaxTTL == 0 {
		c.MaxTTL = HardMaxTTL
	}
	if c.MaxLeases == 0 {
		c.MaxLeases = HardMaxLeases
	}
	if c.MaxTTL < time.Second || c.MaxTTL > HardMaxTTL || c.MaxLeases < 1 || c.MaxLeases > HardMaxLeases {
		return c, nil, errors.New("limits must be TTL 1s..15m and leases 1..1000")
	}
	s := c.Scope
	if (s.Hook != "input" && s.Hook != "forward" && s.Hook != "prerouting") || (s.Protocol != "tcp" && s.Protocol != "udp") || s.Port == 0 {
		return c, nil, errors.New("explicit input/forward hook, tcp/udp protocol and service port required")
	}
	if len(s.Interface) > 15 || !regexp.MustCompile(`^[a-zA-Z0-9_][a-zA-Z0-9_.-]*$`).MatchString(s.Interface) {
		return c, nil, errors.New("explicit ingress interface required (maximum 15 bytes)")
	}
	p, err := netip.ParsePrefix(s.DestinationCIDR)
	if err != nil || p.Addr().Is4In6() || p != p.Masked() || p.Bits() == 0 || !p.Addr().IsGlobalUnicast() {
		return c, nil, errors.New("destination must be a canonical, non-default unicast CIDR")
	}
	var protected []netip.Prefix
	c.ProtectedCIDRs = append([]string(nil), c.ProtectedCIDRs...)
	for _, raw := range c.ProtectedCIDRs {
		p, err := netip.ParsePrefix(raw)
		if err != nil || p.Addr().Is4In6() || p != p.Masked() {
			return c, nil, fmt.Errorf("invalid protected CIDR %q", raw)
		}
		dst, _ := netip.ParsePrefix(c.Scope.DestinationCIDR)
		if p.Overlaps(dst) {
			return c, nil, errors.New("destination scope overlaps protected CIDR")
		}
		protected = append(protected, p)
	}
	if err := normalizeProfiles(&c); err != nil {
		return c, nil, err
	}
	return c, protected, nil
}

// New validates the scope and reconciles immediately. With nil backend it selects
// DryRunBackend or NewNFTBackend. No listener, goroutine or installation is started.
// Call Reconcile periodically to garbage-collect expired rules and state; the nft
// set timeout removes the actual block even if this process has stopped.
// After backend acceptance, New owns its lifetime: an io.Closer backend is closed
// on initialization failure or Controller.Close. Do not share an NFTBackend.
func New(config Config, backend Backend) (*Controller, error) {
	c, protected, err := normalize(config)
	if err != nil {
		return nil, err
	}
	if backend == nil {
		if c.DryRun {
			backend = NewDryRunBackend()
		} else {
			backend, err = NewNFTBackend(c)
			if err != nil {
				return nil, err
			}
		}
	}
	if c.DryRun {
		if _, ok := backend.(*DryRunBackend); !ok {
			return nil, errors.New("DryRun requires DryRunBackend")
		}
	}
	x := &Controller{config: c, protected: protected, backend: backend, leases: make(map[string]Lease)}
	if owner, ok := backend.(interface{ claim() error }); ok {
		if err = owner.claim(); err != nil {
			return nil, err
		}
	}
	ready := false
	defer func() {
		if !ready {
			_ = x.Close()
		}
	}()
	if c.StateFile != "" {
		x.unlock, err = lockState(c.StateFile)
		if err != nil {
			return nil, err
		}
		if err = x.load(); err != nil {
			return nil, err
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err = x.reconcile(ctx); err != nil {
		return nil, err
	}
	ready = true
	return x, nil
}

func fingerprint(c Config) string {
	b, _ := json.Marshal(struct {
		Table, Namespace  string
		Scope             Scope
		Protected         []string
		DryRun            bool
		Profiles          map[string]Profile `json:",omitempty"`
		ProtectedServices []Service          `json:",omitempty"`
	}{c.Table, c.Namespace, c.Scope, c.ProtectedCIDRs, c.DryRun, c.Profiles, c.ProtectedServices})
	if c.Auth != nil {
		b, _ = json.Marshal(struct {
			Network  json.RawMessage
			Identity firewallauth.Scope
		}{b, c.AuthScope})
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func (c *Controller) validate(l Lease) error {
	if err := c.validateAction(l); err != nil {
		return err
	}
	return c.validateBase(l)
}

func (c *Controller) validateBase(l Lease) error {
	if !identifier.MatchString(l.ID) || l.Scope != c.config.Scope {
		return errors.New("invalid ID or scope")
	}
	a, err := netip.ParseAddr(l.Source)
	if err != nil || a.Is4In6() || a.Zone() != "" || !a.IsGlobalUnicast() || a.String() != l.Source {
		return errors.New("source must be one canonical unicast IP address")
	}
	dst, _ := netip.ParsePrefix(c.config.Scope.DestinationCIDR)
	if a.Is4() != dst.Addr().Is4() {
		return errors.New("source and destination address families differ")
	}
	for _, p := range c.protected {
		if p.Contains(a) {
			return errors.New("source overlaps protected CIDR")
		}
	}
	if l.TTLSeconds < 1 || l.TTLSeconds > int64(HardMaxTTL/time.Second) || l.TTLSeconds > ceilSeconds(c.config.MaxTTL) {
		return errors.New("TTL exceeds configured limit")
	}
	now := time.Now()
	if l.ExpiresAt.IsZero() || l.ExpiresAt.After(now.Add(time.Duration(l.TTLSeconds)*time.Second)) || l.ExpiresAt.After(now.Add(c.config.MaxTTL)) {
		return errors.New("invalid expiry")
	}
	return nil
}

func (c *Controller) Create(ctx context.Context, id, source string, ttl time.Duration) (Lease, error) {
	if err := c.authorize(ctx, firewallauth.Lease); err != nil {
		return Lease{}, err
	}
	if err := c.checkApproval(ctx, CreateApprovalDigest(id, source, ttl, time.Time{})); err != nil {
		return Lease{}, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return Lease{}, errors.New("controller closed")
	}
	if ttl < time.Second || ttl > c.config.MaxTTL || ttl%time.Second != 0 {
		return Lease{}, errors.New("TTL must be whole seconds within configured limit")
	}
	l := Lease{ID: id, Source: source, Scope: c.config.Scope, TTLSeconds: int64(ttl / time.Second), ExpiresAt: time.Now().UTC().Add(ttl)}
	return c.create(ctx, l, false)
}

// CreateUntil preserves the exact UTC deadline (RFC3339Nano on the wire).
// Remaining lifetime must be 1ms..MaxTTL on the enforcer's clock. nft truncates
// remaining time to milliseconds; TTLSeconds is metadata, never a renewal input.
// An active same-ID retry must have the same source and deadline.
func (c *Controller) CreateUntil(ctx context.Context, id, source string, expiresAt time.Time) (Lease, error) {
	return c.CreateActionUntil(ctx, id, source, expiresAt, Action{})
}

func (c *Controller) CreateActionUntil(ctx context.Context, id, source string, expiresAt time.Time, action Action) (Lease, error) {
	if err := c.authorize(ctx, firewallauth.Lease); err != nil {
		return Lease{}, err
	}
	if err := c.checkApproval(ctx, CreateApprovalDigest(id, source, 0, expiresAt)); err != nil {
		return Lease{}, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return Lease{}, errors.New("controller closed")
	}
	now := time.Now()
	remaining := expiresAt.Sub(now)
	if expiresAt.IsZero() || remaining < time.Millisecond || remaining > c.config.MaxTTL {
		return Lease{}, errors.New("deadline must be 1ms..MaxTTL in the future")
	}
	l := Lease{ID: id, Source: source, Scope: c.config.Scope, TTLSeconds: ceilSeconds(remaining), ExpiresAt: expiresAt.UTC(), Action: action}
	return c.create(ctx, l, true)
}

func ceilSeconds(d time.Duration) int64 { return int64((d + time.Second - 1) / time.Second) }

// create runs with c.mu held. Deadline validation precedes reconciliation and is
// repeated after durable writes, immediately before handing the lease to a backend.
func (c *Controller) create(ctx context.Context, l Lease, absolute bool) (Lease, error) {
	if err := ctx.Err(); err != nil {
		return Lease{}, err
	}
	if err := c.validate(l); err != nil {
		return Lease{}, err
	}
	if err := c.reconcile(ctx); err != nil {
		return Lease{}, err
	}
	if old, ok := c.leases[l.ID]; ok {
		same := old.TTLSeconds == l.TTLSeconds
		if absolute {
			same = old.ExpiresAt.Equal(l.ExpiresAt)
		}
		if old.Source == l.Source && old.Action == l.Action && same {
			return old, nil
		}
		return Lease{}, ErrConflict
	}
	for _, old := range c.leases {
		if c.selectorsConflict(old, l) {
			return Lease{}, ErrConflict
		}
	}
	if len(c.leases) >= c.config.MaxLeases {
		return Lease{}, ErrLimit
	}
	if err := ctx.Err(); err != nil {
		return Lease{}, err
	}
	if time.Until(l.ExpiresAt) < time.Millisecond {
		return Lease{}, errors.New("lease deadline expired before admission")
	}
	c.leases[l.ID] = l
	if err := c.save(); err != nil {
		delete(c.leases, l.ID)
		return Lease{}, err
	}
	if err := ctx.Err(); err != nil {
		delete(c.leases, l.ID)
		return Lease{}, errors.Join(err, c.save())
	}
	if time.Until(l.ExpiresAt) < time.Millisecond {
		delete(c.leases, l.ID)
		if err := c.save(); err != nil {
			return Lease{}, err
		}
		return Lease{}, errors.New("lease deadline expired before apply")
	}
	if err := c.applyLease(ctx, l); err != nil {
		// Retain durable intent on an ambiguous executor failure. Reconcile retries
		// with the same absolute deadline, never a fresh TTL.
		return Lease{}, &ExecutionError{err}
	}
	return l, nil
}

func (c *Controller) applyLease(ctx context.Context, l Lease) error {
	ctx, cancel := context.WithDeadline(ctx, l.ExpiresAt)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return err
	}
	return c.backend.Apply(ctx, l)
}

func (c *Controller) Delete(ctx context.Context, id string) error {
	if err := c.authorize(ctx, firewallauth.Lease); err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return errors.New("controller closed")
	}
	if err := c.checkApproval(ctx, DeleteApprovalDigest(c.leases[id])); err != nil {
		return err
	}
	if err := c.reconcile(ctx); err != nil {
		return err
	}
	l, ok := c.leases[id]
	if !ok {
		return nil
	}
	delete(c.leases, id)
	if err := c.save(); err != nil {
		c.leases[id] = l
		return err
	}
	if err := c.backend.Delete(ctx, l); err != nil {
		return &ExecutionError{err}
	}
	return nil
}

func (c *Controller) List(ctx context.Context) ([]Lease, error) {
	if err := c.authorize(ctx, firewallauth.Read); err != nil {
		return nil, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil, errors.New("controller closed")
	}
	if c.config.Auth == nil {
		if err := c.reconcile(ctx); err != nil {
			return nil, err
		}
	}
	return sorted(c.leases), nil
}

func sorted(m map[string]Lease) []Lease {
	out := make([]Lease, 0, len(m))
	for _, l := range m {
		out = append(out, l)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func (c *Controller) Reconcile(ctx context.Context) error {
	if err := c.authorize(ctx, firewallauth.Lease); err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return errors.New("controller closed")
	}
	return c.reconcile(ctx)
}

func (c *Controller) authorize(ctx context.Context, action firewallauth.Action) error {
	if c.config.Auth != nil {
		return firewallauth.Require(ctx, action, c.config.AuthScope)
	}
	return nil
}

func (c *Controller) checkApproval(ctx context.Context, digest string) error {
	if c.config.Approvals != nil {
		return c.config.Approvals.Check(ctx, firewallauth.Lease, c.config.AuthScope, digest, firewallauth.Receipt(ctx))
	}
	return nil
}

func CreateApprovalDigest(id, source string, ttl time.Duration, expires time.Time) string {
	return firewallauth.Digest(struct {
		Operation, ID, Source string
		TTL                   time.Duration
		Expires               time.Time
	}{"create", id, source, ttl, expires.UTC()})
}
func DeleteApprovalDigest(l Lease) string {
	return firewallauth.Digest(struct {
		Operation string
		Lease     Lease
	}{"delete", l})
}

func (c *Controller) reconcile(ctx context.Context) error {
	kernel, err := c.backend.List(ctx)
	if err != nil {
		return &ExecutionError{err}
	}
	now := time.Now()
	for _, l := range kernel {
		if err := c.validate(l); err != nil {
			return &ExecutionError{fmt.Errorf("backend lease: %w", err)}
		}
	}
	if !c.initialized && c.config.StateFile == "" {
		selectors := make(map[string]bool)
		for _, l := range kernel {
			if l.ExpiresAt.After(now) {
				for _, old := range c.leases {
					if c.selectorsConflict(old, l) {
						return ErrConflict
					}
				}
				if _, ok := c.leases[l.ID]; ok || selectors[selectorKey(l)] {
					return ErrConflict
				}
				c.leases[l.ID] = l
				selectors[selectorKey(l)] = true
			}
		}
		if len(c.leases) > c.config.MaxLeases {
			return ErrLimit
		}
	}
	for id, l := range c.leases {
		if !l.ExpiresAt.After(now) {
			delete(c.leases, id)
		}
	}
	if err := c.save(); err != nil {
		return err
	}
	for _, l := range kernel {
		want, ok := c.leases[l.ID]
		if !ok || want != l {
			if err := c.backend.Delete(ctx, l); err != nil {
				return &ExecutionError{err}
			}
		}
	}
	for _, l := range c.leases {
		found := false
		for _, k := range kernel {
			if k == l {
				found = true
				break
			}
		}
		if !found {
			if err := c.applyLease(ctx, l); err != nil {
				return &ExecutionError{err}
			}
		}
	}
	c.initialized = true
	return nil
}

// Close closes an io.Closer backend (releasing the nft namespace/table singleton)
// and releases the state-file lock. Existing leases retain their kernel TTL;
// Close does not remove blocks or delete the owned table.
func (c *Controller) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	c.closed = true
	var err error
	if closer, ok := c.backend.(io.Closer); ok {
		err = closer.Close()
	}
	if c.unlock != nil {
		err = errors.Join(err, c.unlock())
	}
	return err
}
