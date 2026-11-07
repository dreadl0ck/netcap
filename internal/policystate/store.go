// Package policystate evaluates native policies in an authoritative transaction.
// No request/event payload is persisted. PostgreSQL serializes the namespace
// (stronger than per-scope/revision locking); SQLite is a fenced WAL singleton.
package policystate

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"math"
	"sort"
	"sync"
	"time"

	"github.com/dreadl0ck/netcap/internal/firewallauth"
	"github.com/dreadl0ck/netcap/internal/firewallstate"
	"github.com/dreadl0ck/netcap/internal/policy"
)

const MaxRevisions = 64
const MaxBytes = 64 << 20
const MaxRequestBytes = 16 << 20

type Principal struct {
	ID    string
	Token string
	Scope firewallstate.Scope
}
type Config struct {
	Auth                        *firewallauth.Authority
	Environment, Target, Origin string
	StateDir                    string
	DatabaseURL                 string
	DatabaseNamespace           string
	Principals                  []Principal
	AllowEffects                bool
	MaxRevisions                int
	MaxStateBytes               int
}
type Request struct {
	Revision string          `json:"revision"`
	Bundle   json.RawMessage `json:"bundle,omitempty"`
	Event    *policy.Event   `json:"event"`
}
type artifact struct {
	p   *policy.Compiled
	raw []byte
}
type Store struct {
	cfg         Config
	disk        *firewallstate.Database
	fingerprint string
	mu          sync.Mutex
	cache       map[string]artifact
	order       []string
	cacheBytes  int
	slots       chan struct{}
	now         func() time.Time
	closed      bool
}

func normalize(cfg Config) (Config, string, error) {
	if cfg.Auth != nil && cfg.DatabaseURL != "" {
		return cfg, "", errors.New("shared identity mode requires a singleton SQLite service; PostgreSQL replicas require a shared identity ledger")
	}
	if cfg.Auth != nil && len(cfg.Principals) > 0 {
		return cfg, "", errors.New("shared authority and legacy state principals are mutually exclusive")
	}
	if cfg.MaxRevisions == 0 {
		cfg.MaxRevisions = MaxRevisions
	}
	if cfg.MaxStateBytes == 0 {
		cfg.MaxStateBytes = MaxBytes
	}
	if cfg.MaxRevisions < 1 || cfg.MaxRevisions > MaxRevisions || cfg.MaxStateBytes < 1024 || cfg.MaxStateBytes > MaxBytes || (len(cfg.Principals) < 1 && cfg.Auth == nil) || len(cfg.Principals) > 100 {
		return cfg, "", errors.New("invalid native policy-state limits")
	}
	if cfg.DatabaseURL != "" && cfg.StateDir != "" || cfg.DatabaseURL == "" && cfg.DatabaseNamespace != "" {
		return cfg, "", errors.New("database URL and state directory are exclusive; namespace requires PostgreSQL")
	}
	cfg.Principals = append([]Principal(nil), cfg.Principals...)
	sort.Slice(cfg.Principals, func(i, j int) bool { return cfg.Principals[i].ID < cfg.Principals[j].ID })
	ids, tokens := map[string]bool{}, map[string]bool{}
	type pin struct {
		ID, TokenHash string
		Scope         firewallstate.Scope
	}
	pins := []pin{}
	for _, p := range cfg.Principals {
		hash := firewallstate.Digest(p.Token)
		if !firewallstate.ValidID(p.ID) || len(p.Token) < 16 || len(p.Token) > 4096 || !p.Scope.Valid() || ids[p.ID] || tokens[hash] {
			return cfg, "", errors.New("invalid/duplicate native state principal")
		}
		ids[p.ID], tokens[hash] = true, true
		pins = append(pins, pin{p.ID, hash, p.Scope})
	}
	raw, _ := json.Marshal(struct {
		Kind             string
		Effects          bool
		Revisions, Bytes int
		Principals       []pin
	}{"native-policy-state/v1", cfg.AllowEffects, cfg.MaxRevisions, cfg.MaxStateBytes, pins})
	return cfg, firewallstate.Digest(string(raw)), nil
}

func New(cfg Config) (*Store, error) {
	cfg, fp, err := normalize(cfg)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var d *firewallstate.Database
	if cfg.DatabaseURL != "" {
		if cfg.DatabaseNamespace == "" {
			cfg.DatabaseNamespace = "netcap_policy_state"
		}
		d, err = firewallstate.OpenPostgres(ctx, cfg.DatabaseURL, cfg.DatabaseNamespace)
	} else {
		d, err = firewallstate.OpenDatabase(cfg.StateDir, "policystate")
	}
	if err != nil {
		return nil, err
	}
	s := &Store{cfg: cfg, disk: d, fingerprint: fp, cache: make(map[string]artifact), slots: make(chan struct{}, 4), now: time.Now}
	if !d.IsPostgres() {
		if err = firewallauth.PinState(ctx, d.DB, firewallauth.Scope{Environment: cfg.Environment, Target: cfg.Target}, cfg.Auth != nil); err != nil {
			d.Close()
			return nil, err
		}
	}
	fail := func(err error) (*Store, error) { _ = d.Close(); return nil, err }
	blob := "BLOB"
	if d.IsPostgres() {
		blob = "BYTEA"
	}
	schema := []string{
		`CREATE TABLE IF NOT EXISTS policy_state_meta(id INTEGER PRIMARY KEY CHECK(id=1),version INTEGER NOT NULL,fingerprint TEXT NOT NULL,last_ns BIGINT NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS policy_states(tenant TEXT NOT NULL,app TEXT NOT NULL,revision TEXT NOT NULL,bundle ` + blob + ` NOT NULL,snapshot ` + blob + ` NOT NULL,accounted BIGINT NOT NULL,watermark BIGINT NOT NULL,expires BIGINT NOT NULL,PRIMARY KEY(tenant,app,revision))`,
	}
	if d.IsPostgres() {
		if err = d.Bootstrap(ctx, fp, schema); err != nil {
			return fail(err)
		}
	} else {
		if _, err = d.DB.ExecContext(ctx, `PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL`); err != nil {
			return fail(err)
		}
		for _, statement := range schema {
			if _, err = d.DB.ExecContext(ctx, statement); err != nil {
				return fail(err)
			}
		}
	}
	tx, err := d.Begin(ctx)
	if err != nil {
		return fail(err)
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `INSERT INTO policy_state_meta VALUES(1,1,?,0) ON CONFLICT(id) DO NOTHING`, fp); err != nil {
		return fail(err)
	}
	if err = s.validate(ctx, tx); err != nil {
		_ = tx.Rollback()
		return fail(err)
	}
	if err = tx.Commit(); err != nil {
		return fail(err)
	}
	return s, nil
}

func validRevision(v string) bool {
	if len(v) != 64 {
		return false
	}
	for _, c := range v {
		if !(c >= 'a' && c <= 'f' || c >= '0' && c <= '9') {
			return false
		}
	}
	return true
}
func (s *Store) scopeAllowed(scope firewallstate.Scope) bool {
	if s.cfg.Auth != nil {
		return scope.Valid()
	}
	for _, p := range s.cfg.Principals {
		if p.Scope == scope {
			return true
		}
	}
	return false
}

func (s *Store) compile(raw []byte, revision string) (artifact, error) {
	if len(raw) == 0 || len(raw) > policy.MaxBundleBytes || !validRevision(revision) {
		return artifact{}, firewallstate.Fail(400, "invalid policy artifact")
	}
	if a, ok := s.cache[revision]; ok && bytes.Equal(a.raw, raw) {
		return a, nil
	}
	b, err := policy.Parse(raw)
	if err != nil {
		return artifact{}, firewallstate.Fail(400, "invalid policy artifact")
	}
	p, err := policy.CompileWithOptions(b, policy.CompileOptions{AllowEffects: s.cfg.AllowEffects})
	if err != nil || p.Revision() != revision {
		return artifact{}, firewallstate.Fail(400, "policy revision/admission mismatch")
	}
	canonical, err := json.Marshal(p.Bundle())
	if err != nil {
		return artifact{}, err
	}
	a := artifact{p, canonical}
	cost := len(canonical) + p.StateProgramBytes()
	if cost > 8<<20 {
		return a, nil
	}
	if _, exists := s.cache[revision]; !exists {
		for len(s.order) >= MaxRevisions || s.cacheBytes+cost > 8<<20 {
			old := s.order[0]
			s.cacheBytes -= len(s.cache[old].raw) + s.cache[old].p.StateProgramBytes()
			delete(s.cache, old)
			s.order = s.order[1:]
		}
		s.order = append(s.order, revision)
		s.cacheBytes += cost
	}
	s.cache[revision] = a
	return a, nil
}

func (s *Store) metadata(ctx context.Context, tx *firewallstate.Transaction) (int64, error) {
	var version, rows int
	var fp string
	var last int64
	err := tx.QueryRowContext(ctx, `SELECT count(*),coalesce(min(version),0),coalesce(min(fingerprint),''),coalesce(min(last_ns),-1) FROM policy_state_meta`).Scan(&rows, &version, &fp, &last)
	if err != nil {
		return 0, err
	}
	if rows != 1 || version != 1 || fp != s.fingerprint || last < 0 || last > math.MaxInt64-int64(24*time.Hour) {
		return 0, errors.New("invalid native policy-state metadata")
	}
	return last, nil
}

func (s *Store) validate(ctx context.Context, tx *firewallstate.Transaction) error {
	last, err := s.metadata(ctx, tx)
	if err != nil {
		return err
	}
	if err := s.checkRows(ctx, tx, last); err != nil {
		return err
	}
	rows, err := tx.QueryContext(ctx, `SELECT tenant,app,revision,bundle,snapshot,accounted,watermark,expires FROM policy_states`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var scope firewallstate.Scope
		var revision string
		var raw, snapshot []byte
		var accounted int
		var watermark, expires int64
		if err = rows.Scan(&scope.Tenant, &scope.App, &revision, &raw, &snapshot, &accounted, &watermark, &expires); err != nil {
			return err
		}
		if !scope.Valid() || !s.scopeAllowed(scope) || watermark > last {
			return errors.New("invalid persisted policy scope/clock")
		}
		a, err := s.compile(raw, revision)
		if err != nil {
			return errors.New("invalid persisted policy artifact")
		}
		if !bytes.Equal(a.raw, raw) {
			return errors.New("noncanonical persisted policy artifact")
		}
		p := a.p.Fork()
		if err = p.ImportState(ctx, snapshot); err != nil {
			return err
		}
		if p.StateStats().AccountedBytes+p.StateProgramBytes() != accounted || p.StateDeadline().UnixNano() != expires || p.StateWatermark().UnixNano() != watermark {
			return errors.New("invalid persisted policy-state accounting")
		}
	}
	return rows.Err()
}

// Startup and runtime enforce the same row invariants before loading snapshots
// or reclaiming expired revisions. Fresh (zero-watermark) forks are never rows.
func (s *Store) checkRows(ctx context.Context, tx *firewallstate.Transaction, last int64) error {
	var count int
	var total, bad int64
	err := tx.QueryRowContext(ctx, `SELECT count(*),coalesce(sum(length(bundle)+length(snapshot)+accounted),0),coalesce(sum(CASE WHEN length(bundle)=0 OR length(bundle)>1048576 OR length(snapshot)=0 OR length(snapshot)>8388608 OR accounted<0 OR watermark<=0 OR watermark>? OR expires<watermark THEN 1 ELSE 0 END),0) FROM policy_states`, last).Scan(&count, &total, &bad)
	if err != nil {
		return err
	}
	if count > s.cfg.MaxRevisions || total > int64(s.cfg.MaxStateBytes) || bad != 0 {
		return errors.New("persisted native policy state exceeds bounds")
	}
	rows, err := tx.QueryContext(ctx, `SELECT tenant,app,revision FROM policy_states`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var scope firewallstate.Scope
		var revision string
		if err := rows.Scan(&scope.Tenant, &scope.App, &revision); err != nil {
			return err
		}
		if !scope.Valid() || !s.scopeAllowed(scope) || !validRevision(revision) {
			return errors.New("invalid persisted policy scope/revision")
		}
	}
	return rows.Err()
}

// Evaluate is a trusted in-process boundary. HTTP callers cannot supply Scope.
// Commit errors return no decision and are never retried, even if commit applied.
func (s *Store) Evaluate(ctx context.Context, scope firewallstate.Scope, req Request) (policy.Decision, error) {
	if s.cfg.Auth != nil && firewallauth.Require(ctx, firewallauth.Evaluate, firewallauth.Scope{Tenant: scope.Tenant, App: scope.App, Environment: s.cfg.Environment, Target: s.cfg.Target}) != nil {
		return policy.Decision{}, firewallstate.Fail(403, "state grant required")
	}
	if !scope.Valid() || !s.scopeAllowed(scope) || !validRevision(req.Revision) || req.Event == nil {
		return policy.Decision{}, firewallstate.Fail(400, "invalid scoped evaluation")
	}
	if err := policy.ValidateEvent(*req.Event); err != nil {
		return policy.Decision{}, firewallstate.Fail(400, "invalid policy event")
	}
	if len(req.Bundle) > policy.MaxBundleBytes {
		return policy.Decision{}, firewallstate.Fail(413, "policy artifact exceeds limit")
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return policy.Decision{}, errors.New("native state closed")
	}
	tx, err := s.disk.Begin(ctx)
	if err != nil {
		return policy.Decision{}, err
	}
	defer tx.Rollback()
	last, err := s.metadata(ctx, tx)
	if err != nil {
		return policy.Decision{}, err
	}
	stamp, err := tx.Clock(ctx, s.now().UnixNano())
	if err != nil {
		return policy.Decision{}, err
	}
	if stamp < last {
		stamp = last
	}
	if stamp <= 0 || stamp > math.MaxInt64-int64(24*time.Hour) {
		return policy.Decision{}, policy.ErrStateClock
	}
	if err := s.checkRows(ctx, tx, last); err != nil {
		return policy.Decision{}, err
	}
	var raw, snapshot []byte
	var oldAccounted int
	var oldWatermark, oldExpiry int64
	err = tx.QueryRowContext(ctx, `SELECT bundle,snapshot,accounted,watermark,expires FROM policy_states WHERE tenant=? AND app=? AND revision=?`, scope.Tenant, scope.App, req.Revision).Scan(&raw, &snapshot, &oldAccounted, &oldWatermark, &oldExpiry)
	exists := err == nil
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return policy.Decision{}, err
	}
	if exists && (oldWatermark <= 0 || oldWatermark > last || oldExpiry < oldWatermark) {
		return policy.Decision{}, policy.ErrSnapshot
	}
	if len(req.Bundle) > 0 {
		a, e := s.compile(req.Bundle, req.Revision)
		if e != nil {
			return policy.Decision{}, e
		}
		if exists && !bytes.Equal(raw, a.raw) {
			return policy.Decision{}, errors.New("persisted artifact mismatch")
		}
		raw = a.raw
	}
	if len(raw) == 0 {
		return policy.Decision{}, firewallstate.Fail(409, "policy artifact required")
	}
	a, err := s.compile(raw, req.Revision)
	if err != nil {
		return policy.Decision{}, err
	}
	if exists && !bytes.Equal(a.raw, raw) {
		return policy.Decision{}, errors.New("noncanonical persisted policy artifact")
	}
	p := a.p.Fork()
	if exists {
		if len(snapshot) > policy.MaxSnapshotBytes || oldWatermark > last {
			return policy.Decision{}, policy.ErrSnapshot
		}
		if err = p.ImportState(ctx, snapshot); err != nil {
			return policy.Decision{}, err
		}
		if p.StateStats().AccountedBytes+p.StateProgramBytes() != oldAccounted || p.StateWatermark().UnixNano() != oldWatermark || p.StateDeadline().UnixNano() != oldExpiry {
			return policy.Decision{}, policy.ErrSnapshot
		}
	}
	d, err := p.EvaluateAt(ctx, *req.Event, time.Unix(0, stamp).UTC())
	if err != nil {
		return policy.Decision{}, err
	}
	state, err := p.ExportState(ctx)
	if err != nil {
		return policy.Decision{}, err
	}
	accounted := p.StateStats().AccountedBytes + p.StateProgramBytes()
	// Only expired revisions may be reclaimed. The global watermark survives.
	if _, err = tx.ExecContext(ctx, `DELETE FROM policy_states WHERE expires<=? AND NOT(tenant=? AND app=? AND revision=?)`, stamp, scope.Tenant, scope.App, req.Revision); err != nil {
		return policy.Decision{}, err
	}
	var count int
	var total int64
	if err = tx.QueryRowContext(ctx, `SELECT count(*),coalesce(sum(length(bundle)+length(snapshot)+accounted),0) FROM policy_states`).Scan(&count, &total); err != nil {
		return policy.Decision{}, err
	}
	if exists {
		total -= int64(len(raw) + len(snapshot) + oldAccounted)
	} else if count >= s.cfg.MaxRevisions {
		return policy.Decision{}, firewallstate.Fail(503, "native policy revision capacity exhausted")
	}
	if total+int64(len(a.raw)+len(state)+accounted) > int64(s.cfg.MaxStateBytes) {
		return policy.Decision{}, firewallstate.Fail(503, "native policy state capacity exhausted")
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO policy_states(tenant,app,revision,bundle,snapshot,accounted,watermark,expires) VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(tenant,app,revision) DO UPDATE SET snapshot=excluded.snapshot,accounted=excluded.accounted,watermark=excluded.watermark,expires=excluded.expires`, scope.Tenant, scope.App, req.Revision, a.raw, state, accounted, stamp, p.StateDeadline().UnixNano())
	if err != nil {
		return policy.Decision{}, err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE policy_state_meta SET last_ns=? WHERE id=1`, stamp); err != nil {
		return policy.Decision{}, err
	}
	if err = tx.Commit(); err != nil {
		return policy.Decision{}, errors.New("native policy state commit unavailable; outcome unknown")
	}
	return d, nil
}

func (s *Store) Ready(ctx context.Context) error {
	if s.cfg.Auth != nil {
		p, ok := firewallauth.FromContext(ctx)
		if !ok {
			return firewallstate.Fail(403, "state read grant required")
		}
		if _, err := p.BoundScope(firewallauth.Read, s.cfg.Environment, s.cfg.Target); err != nil {
			return firewallstate.Fail(403, "state read grant required")
		}
	}
	if err := s.disk.CheckBootstrap(ctx); err != nil {
		return err
	}
	var version, rows int
	var fp string
	var clock int64
	err := s.disk.DB.QueryRowContext(ctx, `SELECT count(*),coalesce(min(version),0),coalesce(min(fingerprint),''),coalesce(min(last_ns),-1) FROM policy_state_meta`).Scan(&rows, &version, &fp, &clock)
	if err != nil {
		return err
	}
	if rows != 1 || version != 1 || fp != s.fingerprint || clock < 0 || clock > math.MaxInt64-int64(24*time.Hour) {
		return errors.New("native policy state not ready")
	}
	return nil
}
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	return s.disk.Close()
}
func (s *Store) ConsistentBackup(ctx context.Context, path string) error {
	if s.cfg.Auth != nil && firewallauth.Require(ctx, firewallauth.Audit, firewallauth.Scope{Tenant: "*", App: "*", Environment: s.cfg.Environment, Target: s.cfg.Target}) != nil {
		return firewallstate.Fail(403, "state backup grant required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.disk.Backup(ctx, path)
}
