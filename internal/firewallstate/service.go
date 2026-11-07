package firewallstate

import (
	"context"
	"database/sql"
	"errors"
	"io"
	"math"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/dreadl0ck/netcap/internal/firewallauth"
)

const MaxKeys = 4096
const MaxWindow = 24 * time.Hour

// Principal scope is configured on the authoritative server, never from requests.
type Principal struct {
	ID    string
	Token string
	Scope Scope
}
type Config struct {
	Auth                        *firewallauth.Authority
	Environment, Target, Origin string
	StateDir                    string
	DatabaseURL                 string
	DatabaseNamespace           string
	Principals                  []Principal
	MaxKeys                     int
}
type Key struct {
	Revision string `json:"revision"`
	Group    string `json:"group"`
}

// Window is a fixed window anchored at its first count, not a sliding window.
type Window struct {
	Mode     string        `json:"mode"`
	Duration time.Duration `json:"duration"`
}
type CountRequest struct {
	Key    Key    `json:"key"`
	Window Window `json:"window"`
}
type CountResult struct {
	Count   int64     `json:"count"`
	Expires time.Time `json:"expires"`
}
type Store interface {
	Count(context.Context, Key, Window, time.Time) (CountResult, error)
}

type Service struct {
	cfg   Config
	disk  *Database
	mu    sync.Mutex
	slots chan struct{}
}

func New(cfg Config) (*Service, error) {
	if cfg.Auth != nil && cfg.DatabaseURL != "" {
		return nil, errors.New("shared identity mode requires a singleton SQLite service; PostgreSQL replicas require a shared identity ledger")
	}
	if cfg.Auth != nil && len(cfg.Principals) > 0 {
		return nil, errors.New("shared authority and legacy state principals are mutually exclusive")
	}
	if cfg.MaxKeys == 0 {
		cfg.MaxKeys = MaxKeys
	}
	if cfg.MaxKeys < 1 || cfg.MaxKeys > MaxKeys || (len(cfg.Principals) < 1 && cfg.Auth == nil) || len(cfg.Principals) > 100 {
		return nil, errors.New("invalid shared-state limits")
	}
	seen := map[string]bool{}
	ids := map[string]bool{}
	for _, p := range cfg.Principals {
		if !ValidID(p.ID) || len(p.Token) < 16 || !p.Scope.Valid() || seen[Digest(p.Token)] || ids[p.ID] {
			return nil, errors.New("invalid/duplicate principal")
		}
		seen[Digest(p.Token)] = true
		ids[p.ID] = true
	}
	cfg.Principals = append([]Principal(nil), cfg.Principals...)
	if cfg.DatabaseURL != "" && cfg.StateDir != "" || cfg.DatabaseURL == "" && cfg.DatabaseNamespace != "" {
		return nil, errors.New("DatabaseURL and StateDir are mutually exclusive; namespace requires PostgreSQL")
	}
	var d *Database
	var err error
	startup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if cfg.DatabaseURL != "" {
		if cfg.DatabaseNamespace == "" {
			cfg.DatabaseNamespace = "netcap_firewall_state"
		}
		d, err = OpenPostgres(startup, cfg.DatabaseURL, cfg.DatabaseNamespace)
	} else {
		d, err = OpenDatabase(cfg.StateDir, "sharedstate")
	}
	if err != nil {
		return nil, err
	}
	s := &Service{cfg: cfg, disk: d, slots: make(chan struct{}, 32)}
	if !d.IsPostgres() {
		if err = firewallauth.PinState(startup, d.DB, firewallauth.Scope{Environment: cfg.Environment, Target: cfg.Target}, cfg.Auth != nil); err != nil {
			d.Close()
			return nil, err
		}
	}
	if d.IsPostgres() {
		err = d.Bootstrap(startup, stateFingerprint(cfg), statePostgresSchema)
	} else {
		_, err = d.DB.Exec(`CREATE TABLE IF NOT EXISTS metadata(version INTEGER NOT NULL); INSERT INTO metadata SELECT 1 WHERE NOT EXISTS(SELECT 1 FROM metadata);
	CREATE TABLE IF NOT EXISTS counters(tenant TEXT NOT NULL,app TEXT NOT NULL,revision TEXT NOT NULL,grp TEXT NOT NULL,duration INTEGER NOT NULL,count INTEGER NOT NULL,expires INTEGER NOT NULL,PRIMARY KEY(tenant,app,revision,grp));
	CREATE TABLE IF NOT EXISTS counter_clock(id INTEGER PRIMARY KEY CHECK(id=1),last_ns INTEGER NOT NULL);
	INSERT OR IGNORE INTO counter_clock SELECT 1,coalesce(max(expires-duration),0) FROM counters;`)
	}
	if err == nil {
		var version, n, bad, metadataRows int
		err = d.DB.QueryRow(`SELECT count(*),min(version) FROM metadata`).Scan(&metadataRows, &version)
		if err == nil {
			err = d.DB.QueryRow(`SELECT count(*),coalesce(sum(CASE WHEN count<1 OR duration<1000000 OR duration>86400000000000 OR length(revision)!=64 OR length(grp)!=64 OR length(tenant)>128 OR length(app)>128 OR expires<=0 THEN 1 ELSE 0 END),0) FROM counters`).Scan(&n, &bad)
		}
		if err == nil && (metadataRows != 1 || version != 1 || n > cfg.MaxKeys || bad != 0) {
			err = errors.New("invalid persisted shared state")
		}
	}
	if err == nil {
		err = validateCounterKeys(d.DB)
	}
	if err == nil {
		var rows int
		var last int64
		err = d.DB.QueryRow(`SELECT count(*),min(last_ns) FROM counter_clock WHERE id=1`).Scan(&rows, &last)
		if err == nil && (rows != 1 || last < 0) {
			err = errors.New("invalid persisted authoritative clock")
		}
	}
	if err != nil {
		_ = d.Close()
		return nil, err
	}
	return s, nil
}

func validateCounterKeys(db *sql.DB) error {
	rows, err := db.Query(`SELECT tenant,app,revision,grp FROM counters`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var scope Scope
		var revision, group string
		if err = rows.Scan(&scope.Tenant, &scope.App, &revision, &group); err != nil {
			return err
		}
		if !scope.Valid() || !validHash(revision) || !validHash(group) {
			return errors.New("invalid persisted counter scope/hash")
		}
	}
	return rows.Err()
}
func (s *Service) Close() error { return s.disk.Close() }
func (s *Service) Backup(ctx context.Context, path string) error {
	if err := s.authorize(ctx, firewallauth.Audit, Scope{Tenant: "*", App: "*"}); err != nil {
		return err
	}
	return s.disk.Backup(ctx, path)
}

// Bind is for trusted in-process callers only. Network callers are bound by token.
func (s *Service) Bind(scope Scope) Store { return &bound{s: s, scope: scope} }

type bound struct {
	s     *Service
	scope Scope
}

func (b *bound) Count(ctx context.Context, k Key, w Window, now time.Time) (CountResult, error) {
	return b.s.count(ctx, b.scope, k, w, now)
}

func (b *bound) Probe(ctx context.Context) error {
	if err := b.s.authorize(ctx, firewallauth.Read, b.scope); err != nil {
		return err
	}
	if !b.scope.Valid() {
		return Fail(400, "invalid bound scope")
	}
	select {
	case b.s.slots <- struct{}{}:
		defer func() { <-b.s.slots }()
	default:
		return Fail(503, "shared-state concurrency exhausted")
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return b.s.checkHealth(ctx)
}

// checkHealth only reads live schema metadata; it never counts, prunes, or
// advances the authoritative clock. Callers own the slot and deadline.
func (s *Service) checkHealth(ctx context.Context) error {
	if err := s.disk.CheckBootstrap(ctx); err != nil {
		return err
	}
	var rows, version int
	var clock int64
	err := s.disk.DB.QueryRowContext(ctx, `SELECT count(*),coalesce(min(version),0),(SELECT last_ns FROM counter_clock WHERE id=1) FROM metadata`).Scan(&rows, &version, &clock)
	if err != nil {
		return err
	}
	if rows != 1 || version != 1 || clock < 0 {
		return Fail(503, "invalid shared-state metadata")
	}
	return nil
}

func validHash(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, r := range s {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f') {
			return false
		}
	}
	return true
}
func (s *Service) count(ctx context.Context, scope Scope, k Key, w Window, now time.Time) (CountResult, error) {
	if err := s.authorize(ctx, firewallauth.Evaluate, scope); err != nil {
		return CountResult{}, err
	}
	if !scope.Valid() || !validHash(k.Revision) || !validHash(k.Group) || w.Mode != "fixed" || w.Duration < time.Millisecond || w.Duration > MaxWindow || !s.disk.IsPostgres() && now.UnixNano() <= 0 {
		return CountResult{}, Fail(400, "invalid counter key/window")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.disk.Begin(ctx)
	if err != nil {
		return CountResult{}, err
	}
	defer tx.Rollback()
	var last int64
	if err = tx.QueryRowContext(ctx, `SELECT last_ns FROM counter_clock WHERE id=1`).Scan(&last); err != nil {
		return CountResult{}, err
	}
	stamp, err := tx.Clock(ctx, now.UnixNano())
	if err != nil {
		return CountResult{}, err
	}
	if stamp < last {
		stamp = last
	}
	if stamp > math.MaxInt64-int64(w.Duration) {
		return CountResult{}, Fail(400, "counter time overflow")
	}
	if _, err = tx.ExecContext(ctx, `UPDATE counter_clock SET last_ns=? WHERE id=1`, stamp); err != nil {
		return CountResult{}, err
	}
	// Expired keys alone can be reclaimed; overload never evicts a live key.
	if _, err = tx.ExecContext(ctx, `DELETE FROM counters WHERE expires<=?`, stamp); err != nil {
		return CountResult{}, err
	}
	var count, expires, duration int64
	err = tx.QueryRowContext(ctx, `SELECT count,expires,duration FROM counters WHERE tenant=? AND app=? AND revision=? AND grp=?`, scope.Tenant, scope.App, k.Revision, k.Group).Scan(&count, &expires, &duration)
	if errors.Is(err, sql.ErrNoRows) {
		var n int
		if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM counters`).Scan(&n); err != nil {
			return CountResult{}, err
		}
		if n >= s.cfg.MaxKeys {
			return CountResult{}, Fail(503, "shared-state capacity exhausted")
		}
		expires = stamp + int64(w.Duration)
		duration = int64(w.Duration)
	} else if err != nil {
		return CountResult{}, err
	} else if duration != int64(w.Duration) {
		return CountResult{}, Fail(409, "window differs for live key")
	}
	if count == math.MaxInt64 {
		return CountResult{}, Fail(503, "counter overflow")
	}
	count++
	_, err = tx.ExecContext(ctx, `INSERT INTO counters VALUES(?,?,?,?,?,?,?) ON CONFLICT(tenant,app,revision,grp) DO UPDATE SET count=excluded.count`, scope.Tenant, scope.App, k.Revision, k.Group, duration, count, expires)
	if err != nil {
		return CountResult{}, err
	}
	if err = tx.Commit(); err != nil {
		return CountResult{}, err
	}
	return CountResult{count, time.Unix(0, expires).UTC()}, nil
}

func (s *Service) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.cfg.Auth != nil && strings.HasPrefix(r.URL.Path, "/api/v1/auth/") {
			s.cfg.Auth.LifecycleHandler(s.cfg.Origin).ServeHTTP(w, r)
			return
		}
		var p *Principal
		for i := range s.cfg.Principals {
			if MatchToken(Bearer(r), s.cfg.Principals[i].Token) {
				p = &s.cfg.Principals[i]
			}
		}
		if s.cfg.Auth != nil {
			identity, err := s.cfg.Auth.Authenticate(r.Context(), Bearer(r))
			if err != nil {
				WriteError(w, Fail(401, "credential rejected"))
				return
			}
			action := firewallauth.Evaluate
			if r.URL.Path == "/api/v1/state/health" {
				action = firewallauth.Read
			}
			scope, err := identity.BoundScope(action, s.cfg.Environment, s.cfg.Target)
			if err != nil {
				WriteError(w, Fail(403, "state grant required"))
				return
			}
			p = &Principal{ID: identity.ID, Scope: Scope{Tenant: scope.Tenant, App: scope.App}}
			r = r.WithContext(firewallauth.WithPrincipal(r.Context(), identity))
		}
		if p == nil {
			WriteError(w, Fail(401, "principal bearer required"))
			return
		}
		if !firewallauth.AllowOrigin(r, s.cfg.Origin) {
			WriteError(w, Fail(403, "browser origins refused"))
			return
		}
		health := r.URL.Path == "/api/v1/state/health"
		if r.URL.Path != "/api/v1/state/count" && !health {
			http.NotFound(w, r)
			return
		}
		method := "POST"
		if health {
			method = "GET"
		}
		if r.Method != method {
			w.Header().Set("Allow", method)
			w.WriteHeader(405)
			return
		}
		select {
		case s.slots <- struct{}{}:
			defer func() { <-s.slots }()
		default:
			WriteError(w, Fail(503, "shared-state concurrency exhausted"))
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		if health {
			if r.URL.RawQuery != "" {
				WriteError(w, Fail(400, "health takes no parameters"))
				return
			}
			if err := s.checkHealth(ctx); err != nil {
				WriteError(w, err)
				return
			}
			WriteJSON(w, 200, struct {
				Ready bool `json:"ready"`
			}{true})
			return
		}
		raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 2048))
		var in CountRequest
		if err != nil || Decode(raw, &in) != nil {
			WriteError(w, Fail(400, "invalid counter request"))
			return
		}
		out, err := s.count(ctx, p.Scope, in.Key, in.Window, time.Now())
		if err != nil {
			WriteError(w, err)
			return
		}
		WriteJSON(w, 200, out)
	})
}

func (s *Service) authorize(ctx context.Context, action firewallauth.Action, scope Scope) error {
	if s.cfg.Auth != nil && firewallauth.Require(ctx, action, firewallauth.Scope{Tenant: scope.Tenant, App: scope.App, Environment: s.cfg.Environment, Target: s.cfg.Target}) != nil {
		return Fail(403, "state grant required")
	}
	return nil
}

type ClientConfig struct {
	URL       string
	Token     string
	Timeout   time.Duration
	Transport http.RoundTripper
}
type Client struct {
	url, token string
	http       *http.Client
	slots      chan struct{}
}

func (c *Client) Close() { c.http.CloseIdleConnections() }

func (c *Client) Probe(ctx context.Context) error {
	select {
	case c.slots <- struct{}{}:
		defer func() { <-c.slots }()
	default:
		return Fail(503, "shared-state client overloaded")
	}
	var out struct {
		Ready bool `json:"ready"`
	}
	if err := RequestJSON(ctx, c.http, "GET", strings.TrimSuffix(c.url, "/")+"/api/v1/state/health", c.token, nil, &out, 2048); err != nil {
		return err
	}
	if !out.Ready {
		return errors.New("shared state not ready")
	}
	return nil
}

func NewClient(cfg ClientConfig) (*Client, error) {
	u, err := Endpoint(cfg.URL)
	if err != nil {
		return nil, err
	}
	if len(cfg.Token) < 16 {
		return nil, errors.New("principal token required")
	}
	return &Client{url: u.String(), token: cfg.Token, http: HTTPClient(cfg.Timeout, cfg.Transport), slots: make(chan struct{}, 32)}, nil
}

// Count never retries a POST: ambiguous network failure may already have counted.
// The supplied timestamp is ignored remotely; the authoritative server owns time.
func (c *Client) Count(ctx context.Context, k Key, w Window, _ time.Time) (CountResult, error) {
	select {
	case c.slots <- struct{}{}:
		defer func() { <-c.slots }()
	default:
		return CountResult{}, Fail(503, "shared-state client overloaded")
	}
	var out CountResult
	err := RequestJSON(ctx, c.http, "POST", strings.TrimSuffix(c.url, "/")+"/api/v1/state/count", c.token, CountRequest{k, w}, &out, 2048)
	if err == nil && (out.Count < 1 || out.Expires.IsZero()) {
		err = errors.New("invalid counter response")
	}
	return out, err
}
