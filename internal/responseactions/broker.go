// Package responseactions dispatches admitted policy intents to operator-configured
// enforcers. Evaluate never waits for network I/O; delivery failure cannot allow a deny.
package responseactions

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"regexp"
	"sync"
	"time"

	"github.com/dreadl0ck/netcap/internal/enforcer"
	"github.com/dreadl0ck/netcap/internal/policy"
	"github.com/dreadl0ck/netcap/internal/runtimeobs"
)

// Scope is configured by the operator, never by a policy. Endpoint is an HTTPS
// origin; TokenEnv names an environment variable resolved once at construction.
type Scope struct {
	Profiles map[string]enforcer.Profile
	// Notification makes Endpoint a preconfigured HTTPS sink.
	// It receives bounded intent metadata only, with no event body or policy URL.
	Notification      bool
	NotificationPath  string
	Endpoint          string
	TokenEnv          string
	Network           enforcer.Scope
	ProtectedCIDRs    []string
	ProtectedServices []enforcer.Service
}

type Config struct {
	Scopes    map[string]Scope
	QueueSize int
	// MaxPending bounds both intent IDs and source/scope reservations, including cooldown.
	MaxPending  int
	MaxReceipts int
	Retention   time.Duration
	TLSConfig   *tls.Config
	// MaxActionsPerMinute caps new admissions across all scopes in a fixed window.
	// Duplicates consume no budget. Queue-full attempts do consume budget.
	MaxActionsPerMinute int
}

type Receipt struct {
	ID        string    `json:"id"`
	Scope     string    `json:"scope"`
	Status    string    `json:"status"`
	Reason    string    `json:"reason,omitempty"`
	At        time.Time `json:"at"`
	ExpiresAt time.Time `json:"expires_at"`
}

type destination struct {
	protectedServices []enforcer.Service
	profiles          map[string]enforcer.Profile
	notification      bool
	notificationPath  string
	endpoint, token   string
	network           enforcer.Scope
	protected         []netip.Prefix
}

type Broker struct {
	Operations              *runtimeobs.Monitor
	queued                  map[string]time.Time
	mu                      sync.Mutex
	scopes                  map[string]destination
	queue                   chan policy.Intent
	seen                    map[string]time.Time
	receipts                []Receipt
	next                    int
	maxPending, maxReceipts int
	retention               time.Duration
	closed                  bool
	ctx                     context.Context
	cancel                  context.CancelFunc
	wg                      sync.WaitGroup
	client                  *http.Client
	maxActions, actions     int
	actionWindow            time.Time
	targets                 map[targetKey]targetReservation
}

type targetKey struct{ scope, source, action string }
type targetReservation struct {
	id             string
	expires, until time.Time
}

var scopeID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$`)
var envID = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

func New(config Config) (*Broker, error) {
	if config.QueueSize == 0 {
		config.QueueSize = 64
	}
	if config.MaxPending == 0 {
		config.MaxPending = 4096
	}
	if config.MaxReceipts == 0 {
		config.MaxReceipts = 4096
	}
	if config.Retention == 0 {
		config.Retention = 15 * time.Minute
	}
	if config.MaxActionsPerMinute == 0 {
		config.MaxActionsPerMinute = 60
	}
	if config.MaxActionsPerMinute < 1 || config.MaxActionsPerMinute > 4096 {
		return nil, errors.New("responseactions: action rate must be 1..4096 per minute")
	}
	if config.QueueSize < 1 || config.QueueSize > 4096 || config.MaxPending < config.QueueSize || config.MaxPending > 65536 || config.MaxReceipts < 1 || config.MaxReceipts > 65536 || config.Retention < time.Second || config.Retention > 24*time.Hour || len(config.Scopes) == 0 || len(config.Scopes) > 128 {
		return nil, errors.New("responseactions: invalid capacity, retention or scopes")
	}
	tc := &tls.Config{MinVersion: tls.VersionTLS12}
	if config.TLSConfig != nil {
		tc = config.TLSConfig.Clone()
		if tc.InsecureSkipVerify || tc.VerifyConnection != nil || tc.VerifyPeerCertificate != nil {
			return nil, errors.New("responseactions: TLS verification overrides forbidden")
		}
		if tc.MinVersion < tls.VersionTLS12 {
			tc.MinVersion = tls.VersionTLS12
		}
	}
	transport := &http.Transport{TLSClientConfig: tc, MaxIdleConns: 8, MaxIdleConnsPerHost: 2, IdleConnTimeout: time.Minute, ResponseHeaderTimeout: 2 * time.Second}
	b := &Broker{Operations: runtimeobs.New("broker"), queued: map[string]time.Time{}, scopes: make(map[string]destination), queue: make(chan policy.Intent, config.QueueSize), seen: make(map[string]time.Time), maxPending: config.MaxPending, maxReceipts: config.MaxReceipts, retention: config.Retention,
		maxActions: config.MaxActionsPerMinute, targets: make(map[targetKey]targetReservation),
		client: &http.Client{Transport: transport, Timeout: 3 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
	for name, s := range config.Scopes {
		if s.NotificationPath == "" {
			s.NotificationPath = "/v1/notifications"
		}
		path, pathErr := url.ParseRequestURI(s.NotificationPath)
		if pathErr != nil || path.IsAbs() || path.Host != "" || path.RawQuery != "" || path.Fragment != "" || len(s.NotificationPath) > 256 {
			return nil, errors.New("responseactions: invalid notification sink path")
		}
		u, err := url.Parse(s.Endpoint)
		if !scopeID.MatchString(name) || err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") || !envID.MatchString(s.TokenEnv) {
			return nil, errors.New("responseactions: invalid scope endpoint or token environment name")
		}
		token := os.Getenv(s.TokenEnv)
		if len(token) < 32 || len(token) > 4096 {
			return nil, errors.New("responseactions: missing or invalid scope token")
		}
		dst, err := netip.ParsePrefix(s.Network.DestinationCIDR)
		if err != nil || dst != dst.Masked() || dst.Bits() == 0 || !dst.Addr().IsGlobalUnicast() || dst.Addr().Is4In6() || (s.Network.Hook != "input" && s.Network.Hook != "forward" && s.Network.Hook != "prerouting") || (s.Network.Protocol != "tcp" && s.Network.Protocol != "udp") || s.Network.Port == 0 || s.Network.Interface == "" {
			return nil, errors.New("responseactions: invalid network scope")
		}
		// Use enforcer admission to validate and copy bootstrap profile authority.
		validator, err := enforcer.New(enforcer.Config{Token: token, Scope: s.Network, Profiles: s.Profiles, ProtectedCIDRs: s.ProtectedCIDRs, ProtectedServices: s.ProtectedServices, DryRun: true}, nil)
		if err != nil {
			return nil, err
		}
		_ = validator.Close()
		profiles := make(map[string]enforcer.Profile, len(s.Profiles))
		for name, p := range s.Profiles {
			p.Services = append([]enforcer.Service(nil), p.Services...)
			profiles[name] = p
		}
		d := destination{endpoint: u.Scheme + "://" + u.Host, token: token, network: s.Network, profiles: profiles, notification: s.Notification, notificationPath: s.NotificationPath, protectedServices: append([]enforcer.Service(nil), s.ProtectedServices...)}
		if len(s.ProtectedCIDRs) > 128 {
			return nil, errors.New("responseactions: too many protected networks")
		}
		for _, raw := range s.ProtectedCIDRs {
			p, err := netip.ParsePrefix(raw)
			if err != nil || p != p.Masked() || p.Addr().Is4In6() {
				return nil, errors.New("responseactions: invalid protected network")
			}
			d.protected = append(d.protected, p)
		}
		b.scopes[name] = d
	}
	b.ctx, b.cancel = context.WithCancel(context.Background())
	b.Operations.Health(true, "ok")
	b.wg.Add(1)
	go b.run()
	return b, nil
}

// Submit requires an independently attributed source from the trusted ingress
// boundary. Never derive trustedSource from HTTP forwarding headers or policy
// Attributes/Fields. A duplicate retains its original deadline, including failures.
// After expiry plus Retention, the same rule/source may start a new lease.
func (b *Broker) Submit(i policy.Intent, trustedSource string) Receipt {
	return b.SubmitFlow(i, trustedSource, nil)
}

func (b *Broker) SubmitFlow(i policy.Intent, trustedSource string, trustedFlow *enforcer.Flow) Receipt {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := time.Now().UTC()
	reject := func(status, reason string) Receipt { return b.record(i, status, reason, now) }
	if b.closed {
		return reject("dropped", "closed")
	}
	d, ok := b.scopes[i.Scope]
	if !ok {
		return reject("failed", "unknown-scope")
	}
	a, err := netip.ParseAddr(i.Source)
	if err != nil || a.Zone() != "" || a.Is4In6() || !a.IsGlobalUnicast() || a.String() != i.Source || trustedSource != i.Source {
		return reject("failed", "untrusted-source")
	}
	dst, _ := netip.ParsePrefix(d.network.DestinationCIDR)
	if a.Is4() != dst.Addr().Is4() {
		return reject("failed", "source-family")
	}
	for _, p := range d.protected {
		if p.Contains(a) {
			return reject("failed", "protected-source")
		}
	}
	if !admittedAction(i, d, trustedFlow) || (i.Target != "client" && i.Target != "source") || len(i.Revision) != 64 || !scopeID.MatchString(i.RuleID) || i.ID != policy.IntentID(i) || i.TTL < time.Second || i.TTL > policy.MaxEffectTTL || i.TTL%time.Second != 0 || i.IssuedAt.After(now) || i.ExpiresAt != i.IssuedAt.Add(i.TTL) || !i.ExpiresAt.After(now) {
		return reject("failed", "invalid-intent")
	}
	b.prune(now)
	if until, exists := b.seen[i.ID]; exists {
		return Receipt{ID: i.ID, Scope: i.Scope, Status: "duplicate", At: now, ExpiresAt: until.Add(-b.retention)}
	}
	key := targetKey{i.Scope, i.Source, actionKey(i)}
	if reservation, exists := b.targets[key]; exists && now.Before(reservation.until) {
		return Receipt{ID: reservation.id, Scope: i.Scope, Status: "duplicate", Reason: "target-reserved", At: now, ExpiresAt: reservation.expires}
	}
	if len(b.seen) >= b.maxPending {
		return reject("dropped", "dedup-capacity")
	}
	if b.actionWindow.IsZero() || now.Sub(b.actionWindow) >= time.Minute {
		b.actionWindow, b.actions = now, 0
	}
	if b.actions >= b.maxActions {
		return reject("dropped", "creation-rate")
	}
	b.actions++
	b.seen[i.ID] = i.ExpiresAt.Add(b.retention)
	b.targets[key] = targetReservation{i.ID, i.ExpiresAt, i.ExpiresAt.Add(b.retention)}
	select {
	case b.queue <- i:
		b.queued[i.ID] = now
		return reject("requested", "")
	default:
		return reject("dropped", "queue-full")
	}
}

func (b *Broker) record(i policy.Intent, status, reason string, now time.Time) Receipt {
	// Rejected direct callers cannot turn bounded receipt slots into unbounded data.
	if len(i.ID) > 48 {
		i.ID = ""
	}
	if len(i.Scope) > 128 {
		i.Scope = ""
	}
	r := Receipt{ID: i.ID, Scope: i.Scope, Status: status, Reason: reason, At: now, ExpiresAt: i.ExpiresAt}
	if len(b.receipts) < b.maxReceipts {
		b.receipts = append(b.receipts, r)
	} else {
		b.receipts[b.next] = r
		b.next = (b.next + 1) % b.maxReceipts
	}
	return r
}

// Receipts is a bounded chronological snapshot. No source values or tokens appear.
func (b *Broker) Receipts() []Receipt {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.prune(time.Now())
	result := make([]Receipt, 0, len(b.receipts))
	for n := 0; n < len(b.receipts); n++ {
		r := b.receipts[(b.next+n)%len(b.receipts)]
		result = append(result, r)
	}
	return result
}

func (b *Broker) prune(now time.Time) {
	for key, reservation := range b.targets {
		if !now.Before(reservation.until) {
			delete(b.targets, key)
		}
	}
	for id, until := range b.seen {
		if !now.Before(until) {
			delete(b.seen, id)
		}
	}
	old := false
	for _, r := range b.receipts {
		if now.Sub(r.At) > b.retention {
			old = true
			break
		}
	}
	if !old {
		return
	}
	retained := make([]Receipt, 0, len(b.receipts))
	for n := 0; n < len(b.receipts); n++ {
		r := b.receipts[(b.next+n)%len(b.receipts)]
		if now.Sub(r.At) <= b.retention {
			retained = append(retained, r)
		}
	}
	b.receipts, b.next = retained, 0
}

func (b *Broker) run() {
	defer b.wg.Done()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case i, ok := <-b.queue:
			if !ok {
				return
			}
			b.mu.Lock()
			queued := b.queued[i.ID]
			delete(b.queued, i.ID)
			b.mu.Unlock()
			if !queued.IsZero() {
				b.Operations.Observe("queue", queued, "ok")
			}
			start := time.Now()
			status, reason := b.deliver(i)
			b.Operations.Observe("delivery", start, status)
			condition := "ok"
			if status == "failed" {
				condition = "delivery_failed"
			}
			b.mu.Lock()
			if !b.closed {
				b.Operations.Health(status != "failed", condition)
			}
			b.record(i, status, reason, time.Now().UTC())
			b.mu.Unlock()
		case now := <-ticker.C:
			b.mu.Lock()
			b.prune(now)
			b.mu.Unlock()
		}
	}
}

func (b *Broker) Close() error {
	b.mu.Lock()
	if !b.closed {
		b.closed = true
		b.Operations.Health(false, "closed")
		b.cancel()
		close(b.queue)
	}
	b.mu.Unlock()
	b.wg.Wait()
	b.client.CloseIdleConnections()
	return nil
}
