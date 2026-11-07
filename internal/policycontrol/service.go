// Package policycontrol manages one in-process policy attachment. The caller must
// give it exclusive ownership of Target.SetPolicy for the service lifetime.
package policycontrol

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"time"

	"github.com/dreadl0ck/netcap/internal/firewallauth"
	"github.com/dreadl0ck/netcap/internal/policy"
	"github.com/mark3labs/mcp-go/server"
	_ "modernc.org/sqlite"
)

const (
	MaxInputBytes = 256 << 10
	MaxRevisions  = 64
	MaxAudit      = 2048
	MaxReceipts   = 1024
	MaxEvents     = 1000
)

type Target interface {
	Policy() *policy.Compiled
	SetPolicy(*policy.Compiled)
}

// Managed must be explicitly true to enable writes and restart recovery.
// ReadOnly overrides Managed. StateDir is required only in managed mode.
type Config struct {
	Approvals      *firewallauth.Approvals
	Auth           *firewallauth.Authority
	Scope          firewallauth.Scope
	Origin         string
	StdioPrincipal *firewallauth.Principal
	Token          string
	ReadOnly       bool
	StateDir       string
	Managed        bool
	// AllowEffects is immutable host admission, including replay and recovery.
	AllowEffects bool
}

type Service struct {
	cfg       Config
	target    Target
	db        *sql.DB
	ownership *sql.DB
	lock      chan struct{}
	slots     chan struct{}
	httpSlots chan struct{}
	closed    bool
	mcp       *server.MCPServer
}

type Request struct {
	Approval         *firewallauth.ApprovalRequest `json:"approval,omitempty"`
	Receipt          string                        `json:"receipt,omitempty"`
	Bundle           string                        `json:"bundle,omitempty"`
	Revision         string                        `json:"revision,omitempty"`
	OtherRevision    string                        `json:"other_revision,omitempty"`
	ExpectedRevision string                        `json:"expected_revision,omitempty"`
	IdempotencyKey   string                        `json:"idempotency_key,omitempty"`
	Event            policy.Event                  `json:"event,omitempty"`
	Events           []policy.Event                `json:"events,omitempty"`
	Limit            int                           `json:"limit,omitempty"`
}

type Revision struct {
	Revision string          `json:"revision"`
	Bundle   json.RawMessage `json:"bundle"`
}

func ApprovalDigest(operation string, r Request) string {
	r.Receipt = ""
	r.Approval = nil
	return firewallauth.Digest(struct {
		Operation string  `json:"operation"`
		Request   Request `json:"request"`
	}{operation, r})
}

type Deployment struct {
	Revision         string `json:"revision"`
	PreviousRevision string `json:"previous_revision"`
}

type Audit struct {
	ID               int64  `json:"id"`
	Time             string `json:"time"`
	Operation        string `json:"operation"`
	Revision         string `json:"revision"`
	PreviousRevision string `json:"previous_revision"`
}

type apiError struct {
	status  int
	message string
}

func (e *apiError) Error() string              { return e.message }
func failure(status int, message string) error { return &apiError{status, message} }

func New(cfg Config, target Target) (*Service, error) {
	if cfg.Approvals != nil && cfg.Auth == nil {
		return nil, errors.New("approval protection requires identity authority")
	}
	if cfg.Token == "" && cfg.Auth == nil {
		return nil, errors.New("policycontrol: nonempty administrative token required")
	}
	if target == nil || target.Policy() == nil {
		return nil, errors.New("policycontrol: initial compiled policy required")
	}
	cfg.ReadOnly = cfg.ReadOnly || !cfg.Managed
	s := &Service{cfg: cfg, target: target, lock: make(chan struct{}, 1), slots: make(chan struct{}, 8), httpSlots: make(chan struct{}, 8)}
	if _, _, err := s.compileBundle(target.Policy()); err != nil {
		return nil, err
	}
	if !cfg.ReadOnly {
		if cfg.StateDir == "" {
			return nil, errors.New("policycontrol: managed mode requires StateDir")
		}
		if err := s.open(); err != nil {
			if s.db != nil {
				_ = s.db.Close()
			}
			if s.ownership != nil {
				_ = s.ownership.Close()
			}
			return nil, err
		}
	}
	s.mcp = s.newMCP()
	return s, nil
}

func (s *Service) acquire(ctx context.Context) error {
	select {
	case s.lock <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (s *Service) release() { <-s.lock }

// Close releases the managed-state singleton lock. Stop transports before Close.
func (s *Service) Close() error {
	_ = s.acquire(context.Background())
	defer s.release()
	if s.closed {
		return nil
	}
	s.closed = true
	var err error
	if s.db != nil {
		err = s.db.Close()
	}
	if s.ownership != nil {
		err = errors.Join(err, s.ownership.Close())
	}
	return err
}

func compile(raw []byte) (*policy.Compiled, []byte, error) {
	return compileAdmitted(raw, false)
}

func (s *Service) compile(raw []byte) (*policy.Compiled, []byte, error) {
	return compileAdmitted(raw, s.cfg.AllowEffects)
}

func compileAdmitted(raw []byte, allowEffects bool) (*policy.Compiled, []byte, error) {
	if len(raw) == 0 || len(raw) > MaxInputBytes {
		return nil, nil, failure(400, "bundle must contain 1..262144 bytes")
	}
	b, err := policy.Parse(raw)
	if err != nil {
		return nil, nil, failure(400, "invalid policy bundle: "+err.Error())
	}
	c, err := policy.CompileWithOptions(b, policy.CompileOptions{AllowEffects: allowEffects})
	if err != nil {
		return nil, nil, failure(400, "invalid policy bundle: "+err.Error())
	}
	canonical, err := json.Marshal(c.Bundle())
	if err != nil {
		return nil, nil, err
	}
	if len(canonical) > MaxInputBytes {
		return nil, nil, failure(400, "canonical bundle exceeds limit")
	}
	return c, canonical, nil
}

func (s *Service) open() error {
	if err := os.MkdirAll(s.cfg.StateDir, 0700); err != nil {
		return err
	}
	info, err := os.Lstat(s.cfg.StateDir)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return errors.New("policycontrol: StateDir must be a private directory (0700)")
	}
	// Hold a separate, uncancellable connection: database/sql may discard a
	// cancelled transaction's connection and thereby release its SQLite locks.
	lockPath := filepath.Join(s.cfg.StateDir, "policycontrol.lock")
	if err := stateFile(lockPath); err != nil {
		return err
	}
	s.ownership, err = sql.Open("sqlite", sqlitePath(lockPath))
	if err != nil {
		return err
	}
	s.ownership.SetMaxOpenConns(1)
	if _, err = s.ownership.Exec(`PRAGMA busy_timeout=0; PRAGMA locking_mode=EXCLUSIVE; BEGIN EXCLUSIVE;`); err != nil {
		return fmt.Errorf("policycontrol: StateDir already owned: %w", err)
	}
	path := filepath.Join(s.cfg.StateDir, "policycontrol.sqlite")
	if err := stateFile(path); err != nil {
		return err
	}
	s.db, err = sql.Open("sqlite", sqlitePath(path))
	if err != nil {
		return err
	}
	s.db.SetMaxOpenConns(1)
	if err := firewallauth.PinState(context.Background(), s.db, s.cfg.Scope, s.cfg.Auth != nil); err != nil {
		return err
	}
	// EXCLUSIVE in rollback-journal mode holds the OS lock until Close, including
	// between transactions: a second service must never attach this database.
	_, err = s.db.Exec(`PRAGMA busy_timeout=0; PRAGMA journal_mode=DELETE;
		PRAGMA synchronous=FULL; PRAGMA locking_mode=EXCLUSIVE;
		BEGIN EXCLUSIVE;
		CREATE TABLE IF NOT EXISTS metadata (version INTEGER NOT NULL);
		INSERT INTO metadata SELECT 1 WHERE NOT EXISTS (SELECT 1 FROM metadata);
		CREATE TABLE IF NOT EXISTS revisions (seq INTEGER PRIMARY KEY AUTOINCREMENT, revision TEXT UNIQUE NOT NULL, bundle BLOB NOT NULL);
		CREATE TABLE IF NOT EXISTS deployment (singleton INTEGER PRIMARY KEY CHECK(singleton=1), revision TEXT NOT NULL, previous TEXT NOT NULL);
		CREATE TABLE IF NOT EXISTS audit (id INTEGER PRIMARY KEY AUTOINCREMENT, time TEXT NOT NULL, operation TEXT NOT NULL, revision TEXT NOT NULL, previous TEXT NOT NULL);
		CREATE TABLE IF NOT EXISTS receipts (seq INTEGER PRIMARY KEY AUTOINCREMENT, key TEXT UNIQUE NOT NULL, fingerprint TEXT NOT NULL, response BLOB NOT NULL);
		COMMIT;`)
	if err != nil {
		return fmt.Errorf("policycontrol state (one service per StateDir): %w", err)
	}
	var version int
	if err = s.db.QueryRow(`SELECT version FROM metadata`).Scan(&version); err != nil {
		return err
	}
	if version != 1 {
		return fmt.Errorf("policycontrol: unsupported state schema %d", version)
	}
	for _, check := range []struct {
		query string
		max   int
	}{
		{`SELECT COUNT(*) FROM metadata`, 1},
		{`SELECT COUNT(*) FROM revisions`, MaxRevisions},
		{`SELECT COUNT(*) FROM audit`, MaxAudit},
		{`SELECT COUNT(*) FROM receipts`, MaxReceipts},
		{`SELECT COUNT(*) FROM revisions WHERE length(bundle)>262144 OR length(revision)>64`, 0},
		{`SELECT COUNT(*) FROM receipts WHERE length(response)>262144 OR length(key)>128 OR length(fingerprint)>64`, 0},
	} {
		var count int
		if err := s.db.QueryRow(check.query).Scan(&count); err != nil {
			return err
		}
		if count > check.max {
			return errors.New("policycontrol: persisted state exceeds bounds")
		}
	}
	rows, err := s.db.Query(`SELECT revision,bundle FROM revisions`)
	if err != nil {
		return err
	}
	compiled := map[string]*policy.Compiled{}
	for rows.Next() {
		var rev string
		var raw []byte
		if err = rows.Scan(&rev, &raw); err != nil {
			break
		}
		var c *policy.Compiled
		c, _, err = s.compile(raw)
		if err != nil {
			break
		}
		if c.Revision() != rev {
			err = errors.New("policycontrol: persisted revision digest mismatch")
			break
		}
		compiled[rev] = c
	}
	rowErr := rows.Err()
	_ = rows.Close()
	if err != nil {
		return err
	}
	if rowErr != nil {
		return rowErr
	}
	var active, previous string
	err = s.db.QueryRow(`SELECT revision,previous FROM deployment WHERE singleton=1`).Scan(&active, &previous)
	if errors.Is(err, sql.ErrNoRows) {
		if len(compiled) != 0 {
			return errors.New("policycontrol: persisted deployment missing")
		}
		c, raw, e := s.compileBundle(s.target.Policy())
		if e != nil {
			return e
		}
		tx, e := s.db.Begin()
		if e != nil {
			return e
		}
		defer tx.Rollback()
		if _, e = tx.Exec(`INSERT INTO revisions(revision,bundle) VALUES(?,?)`, c.Revision(), raw); e != nil {
			return e
		}
		if _, e = tx.Exec(`INSERT INTO deployment VALUES(1,?, '')`, c.Revision()); e != nil {
			return e
		}
		return tx.Commit()
	}
	if err != nil {
		return err
	}
	if compiled[active] == nil || (previous != "" && compiled[previous] == nil) {
		return errors.New("policycontrol: persisted deployment references missing revision")
	}
	if len(compiled) > MaxRevisions {
		return errors.New("policycontrol: persisted revision retention exceeded")
	}
	s.target.SetPolicy(compiled[active])
	return nil
}

func sqlitePath(path string) string {
	abs, _ := filepath.Abs(path)
	return (&url.URL{Scheme: "file", Path: abs}).String()
}

func stateFile(path string) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if err == nil {
		return f.Close()
	}
	if !errors.Is(err, os.ErrExist) {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return errors.New("policycontrol: state files must be private regular files (0600)")
	}
	return nil
}

func (s *Service) compileBundle(c *policy.Compiled) (*policy.Compiled, []byte, error) {
	if c == nil {
		return nil, nil, failure(503, "target policy unavailable")
	}
	raw, err := json.Marshal(c.Bundle())
	if err != nil {
		return nil, nil, err
	}
	return s.compile(raw)
}

// Execute is the common REST/MCP operation boundary. Evaluate only uses synthetic
// caller-supplied events and never invokes Target.SetPolicy or an upstream.
func (s *Service) Execute(ctx context.Context, operation string, r Request) (any, error) {
	if operation == "approval" {
		if s.cfg.Approvals == nil || r.Approval == nil || r.Approval.Scope != s.cfg.Scope {
			return nil, failure(403, "approval unavailable or foreign scope")
		}
		receipt, err := s.cfg.Approvals.Issue(ctx, *r.Approval)
		if err != nil {
			return nil, failure(403, "separate authorized approver required")
		}
		return map[string]string{"receipt": receipt}, nil
	}
	_, hasPrincipal := firewallauth.FromContext(ctx)
	if s.cfg.Auth != nil || hasPrincipal {
		if err := firewallauth.Require(ctx, firewallauth.Operation(operation), s.cfg.Scope); err != nil {
			return nil, failure(403, "policy grant required")
		}
	}
	if s.cfg.Approvals != nil {
		if err := s.cfg.Approvals.Check(ctx, firewallauth.Operation(operation), s.cfg.Scope, ApprovalDigest(operation, r), r.Receipt); err != nil {
			return nil, failure(403, "valid unused approval receipt required")
		}
	}
	if len(r.Events) > MaxEvents {
		return nil, failure(400, "simulation exceeds 1000 events")
	}
	data, err := json.Marshal(r)
	if err != nil || len(data) > MaxInputBytes {
		return nil, failure(413, "request exceeds input limit")
	}
	select {
	case s.slots <- struct{}{}:
		defer func() { <-s.slots }()
	default:
		return nil, failure(429, "administrative concurrency limit reached")
	}
	if err = s.acquire(ctx); err != nil {
		return nil, err
	}
	defer s.release()
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	if s.closed {
		return nil, failure(503, "service closed")
	}
	switch operation {
	case "capabilities":
		return map[string]any{"api_version": 1, "read_only": s.cfg.ReadOnly, "managed": !s.cfg.ReadOnly,
			"allow_effects": s.cfg.AllowEffects,
			"scope":         "single configured target", "coordination": "per-process; exclusive StateDir singleton", "runtime_configuration_mutable": false,
			"max_input_bytes": MaxInputBytes, "max_revisions": MaxRevisions, "max_audit": MaxAudit, "idempotency_window": MaxReceipts,
			"max_concurrency": 8, "max_events": MaxEvents, "replay": "synthetic events only; no network; fresh counters per replay, shared within replay", "audit_scope": "successful stage/activate/rollback transactions"}, nil
	case "check":
		c, _, e := s.compile([]byte(r.Bundle))
		if e != nil {
			return nil, e
		}
		return map[string]any{"valid": true, "revision": c.Revision()}, nil
	case "evaluate":
		c, e := s.resolve(ctx, r.Revision)
		if e != nil {
			return nil, e
		}
		if e = ctx.Err(); e != nil {
			return nil, e
		}
		if r.Events != nil && !reflect.ValueOf(r.Event).IsZero() {
			return nil, failure(400, "use event or events, not both")
		}
		events := r.Events
		if events == nil {
			events = []policy.Event{r.Event}
		}
		decisions, e := c.Simulate(events)
		if e != nil {
			return nil, failure(400, "synthetic evaluation failed: "+e.Error())
		}
		if e = ctx.Err(); e != nil {
			return nil, e
		}
		if r.Events == nil {
			return decisions[0], nil
		}
		return decisions, nil
	case "revision":
		c, e := s.resolve(ctx, r.Revision)
		if e != nil {
			return nil, e
		}
		raw, e := json.Marshal(c.Bundle())
		return Revision{c.Revision(), raw}, e
	case "revisions":
		return s.revisions(ctx)
	case "diff":
		a, e := s.resolve(ctx, r.Revision)
		if e != nil {
			return nil, e
		}
		b, e := s.resolve(ctx, r.OtherRevision)
		if e != nil {
			return nil, e
		}
		x, _ := json.Marshal(a.Bundle())
		y, _ := json.Marshal(b.Bundle())
		// Return digests and top-level changed fields, never two unbounded bundles.
		var am, bm map[string]json.RawMessage
		_ = json.Unmarshal(x, &am)
		_ = json.Unmarshal(y, &bm)
		changed := []string{}
		for k, v := range am {
			if !bytes.Equal(v, bm[k]) {
				changed = append(changed, k)
			}
		}
		for k := range bm {
			if _, ok := am[k]; !ok {
				changed = append(changed, k)
			}
		}
		sort.Strings(changed)
		return map[string]any{"revision": a.Revision(), "other_revision": b.Revision(), "changed_fields": changed}, nil
	case "audit":
		return s.audit(ctx, r.Limit)
	case "stage", "activate", "rollback":
		if s.cfg.ReadOnly {
			return nil, failure(403, "file/GitOps mode is read-only; managed mode must be explicitly enabled")
		}
		return s.mutate(ctx, operation, r)
	default:
		return nil, failure(404, "unknown policy operation")
	}
}

func (s *Service) resolve(ctx context.Context, revision string) (*policy.Compiled, error) {
	c := s.target.Policy()
	if c == nil {
		return nil, failure(503, "target policy unavailable")
	}
	if revision == "" || revision == c.Revision() {
		admitted, _, err := s.compileBundle(c)
		return admitted, err
	}
	if s.db == nil {
		return nil, failure(404, "revision not retained")
	}
	var raw []byte
	if err := s.db.QueryRowContext(ctx, `SELECT bundle FROM revisions WHERE revision=?`, revision).Scan(&raw); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, failure(404, "revision not retained")
		}
		return nil, err
	}
	c, _, err := s.compile(raw)
	return c, err
}

func (s *Service) revisions(ctx context.Context) (any, error) {
	if s.db == nil {
		return []string{s.target.Policy().Revision()}, nil
	}
	rows, err := s.db.QueryContext(ctx, `SELECT revision FROM revisions ORDER BY seq DESC LIMIT ?`, MaxRevisions)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []string{}
	for rows.Next() {
		var rev string
		if err = rows.Scan(&rev); err != nil {
			return nil, err
		}
		result = append(result, rev)
	}
	return result, rows.Err()
}

func (s *Service) audit(ctx context.Context, limit int) (any, error) {
	if limit == 0 {
		limit = 100
	}
	if limit < 1 || limit > MaxAudit {
		return nil, failure(400, "audit limit must be 1..2048")
	}
	result := []Audit{}
	if s.db == nil {
		return result, nil
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id,time,operation,revision,previous FROM audit ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var a Audit
		if err = rows.Scan(&a.ID, &a.Time, &a.Operation, &a.Revision, &a.PreviousRevision); err != nil {
			return nil, err
		}
		result = append(result, a)
	}
	return result, rows.Err()
}

func (s *Service) mutate(ctx context.Context, op string, r Request) (any, error) {
	if len(r.IdempotencyKey) < 1 || len(r.IdempotencyKey) > 128 {
		return nil, failure(400, "idempotency_key must contain 1..128 bytes")
	}
	encoded, _ := json.Marshal(struct {
		Operation string
		Request   Request
	}{op, r})
	digest := sha256.Sum256(encoded)
	fingerprint := hex.EncodeToString(digest[:])
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var oldFingerprint string
	var response []byte
	err = tx.QueryRowContext(ctx, `SELECT fingerprint,response FROM receipts WHERE key=?`, r.IdempotencyKey).Scan(&oldFingerprint, &response)
	if err == nil {
		if oldFingerprint != fingerprint {
			return nil, failure(409, "idempotency key reused with different request")
		}
		return json.RawMessage(response), nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	var active, previous string
	if err = tx.QueryRowContext(ctx, `SELECT revision,previous FROM deployment WHERE singleton=1`).Scan(&active, &previous); err != nil {
		return nil, err
	}
	var c *policy.Compiled
	var result any
	if op == "stage" {
		var raw []byte
		c, raw, err = s.compile([]byte(r.Bundle))
		if err != nil {
			return nil, err
		}
		if _, err = tx.ExecContext(ctx, `INSERT OR IGNORE INTO revisions(revision,bundle) VALUES(?,?)`, c.Revision(), raw); err != nil {
			return nil, err
		}
		result = map[string]string{"revision": c.Revision()}
	} else {
		if r.ExpectedRevision == "" || r.ExpectedRevision != active {
			return nil, failure(409, "expected_revision does not match active revision")
		}
		rev := r.Revision
		if op == "rollback" && rev == "" {
			rev = previous
		}
		if rev == "" {
			return nil, failure(409, "no rollback revision")
		}
		var raw []byte
		if err = tx.QueryRowContext(ctx, `SELECT bundle FROM revisions WHERE revision=?`, rev).Scan(&raw); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return nil, failure(404, "revision not retained; stage before activation")
			}
			return nil, err
		}
		c, _, err = s.compile(raw)
		if err != nil {
			return nil, err
		}
		if c.Revision() != active {
			if _, err = tx.ExecContext(ctx, `UPDATE deployment SET revision=?,previous=? WHERE singleton=1`, c.Revision(), active); err != nil {
				return nil, err
			}
			previous = active
		}
		result = Deployment{c.Revision(), previous}
	}
	response, err = json.Marshal(result)
	if err != nil {
		return nil, err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO audit(time,operation,revision,previous) VALUES(?,?,?,?)`, time.Now().UTC().Format(time.RFC3339Nano), op, c.Revision(), active); err != nil {
		return nil, err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO receipts(key,fingerprint,response) VALUES(?,?,?)`, r.IdempotencyKey, fingerprint, response); err != nil {
		return nil, err
	}
	for _, q := range []string{
		`DELETE FROM audit WHERE id NOT IN (SELECT id FROM audit ORDER BY id DESC LIMIT 2048)`,
		`DELETE FROM receipts WHERE seq NOT IN (SELECT seq FROM receipts ORDER BY seq DESC LIMIT 1024)`,
		`DELETE FROM revisions WHERE revision NOT IN (SELECT revision FROM deployment UNION SELECT previous FROM deployment) AND seq NOT IN (SELECT seq FROM revisions ORDER BY seq DESC LIMIT 62)`,
	} {
		if _, err = tx.ExecContext(ctx, q); err != nil {
			return nil, err
		}
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	// The durable desired state wins on restart if the process stops here.
	if op != "stage" && c.Revision() != active {
		s.target.SetPolicy(c)
	}
	return result, nil
}
