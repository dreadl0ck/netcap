package firewallfleet

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"slices"
	"sync"
	"time"

	"github.com/dreadl0ck/netcap/internal/firewallstate"
)

type Service struct {
	cfg       Config
	disk      *firewallstate.Database
	mu        sync.Mutex
	slots     chan struct{}
	httpSlots chan struct{}
	artifacts map[string]revision
	enrolled  map[string]Enrollment
}

func New(cfg Config) (*Service, error) {
	if cfg.Token == "" && len(cfg.Identities) == 0 {
		return nil, errors.New("administrative identity required")
	}
	if cfg.Token != "" && len(cfg.Token) < 16 {
		return nil, errors.New("admin token needs at least 16 bytes")
	}
	if len(cfg.Targets) > MaxTargets || len(cfg.Identities) > 100 {
		return nil, errors.New("identity limit exceeded")
	}
	seen := map[string]bool{}
	if cfg.Token != "" {
		seen[firewallstate.Digest(cfg.Token)] = true
	}
	ids := map[string]bool{}
	for _, p := range cfg.Identities {
		if !firewallstate.ValidID(p.ID) || !p.Scope.Valid() || len(p.Token) < 16 || seen[firewallstate.Digest(p.Token)] || ids[p.ID] {
			return nil, errors.New("invalid administrative identity")
		}
		seen[firewallstate.Digest(p.Token)] = true
		ids[p.ID] = true
	}
	ids = map[string]bool{}
	for _, p := range cfg.Targets {
		if !firewallstate.ValidID(p.ID) || !p.Scope.Valid() || len(p.Token) < 16 || seen[firewallstate.Digest(p.Token)] || ids[p.ID] {
			return nil, errors.New("invalid target enrollment")
		}
		seen[firewallstate.Digest(p.Token)] = true
		ids[p.ID] = true
	}
	cfg.Identities = append([]Identity(nil), cfg.Identities...)
	cfg.Targets = append([]Enrollment(nil), cfg.Targets...)
	if cfg.DatabaseURL != "" && cfg.StateDir != "" || cfg.DatabaseURL == "" && cfg.DatabaseNamespace != "" {
		return nil, errors.New("DatabaseURL and StateDir are mutually exclusive; namespace requires PostgreSQL")
	}
	startup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var d *firewallstate.Database
	var err error
	if cfg.DatabaseURL != "" {
		if cfg.DatabaseNamespace == "" {
			cfg.DatabaseNamespace = "netcap_firewall_fleet"
		}
		d, err = firewallstate.OpenPostgres(startup, cfg.DatabaseURL, cfg.DatabaseNamespace)
	} else {
		d, err = firewallstate.OpenDatabase(cfg.StateDir, "fleet")
	}
	if err != nil {
		return nil, err
	}
	s := &Service{cfg: cfg, disk: d, slots: make(chan struct{}, 16), httpSlots: make(chan struct{}, 16), artifacts: map[string]revision{}, enrolled: map[string]Enrollment{}}
	if d.IsPostgres() {
		err = d.Bootstrap(startup, fleetFingerprint(cfg), fleetPostgresSchema)
	} else {
		_, err = d.DB.Exec(`CREATE TABLE IF NOT EXISTS fleet (id INTEGER PRIMARY KEY CHECK(id=1), snapshot BLOB NOT NULL);
	CREATE TABLE IF NOT EXISTS artifacts(key TEXT PRIMARY KEY,tenant TEXT NOT NULL,app TEXT NOT NULL,revision TEXT NOT NULL,bundle BLOB NOT NULL)`)
	}
	if err != nil {
		_ = d.Close()
		return nil, err
	}
	if !d.IsPostgres() {
		err = s.loadArtifacts()
	}
	if err != nil {
		_ = d.Close()
		return nil, err
	}
	err = s.transaction(startup, func(st *snapshot) error {
		if err := validate(st, cfg.AllowEffects); err != nil {
			return err
		}
		// Omitted enrollments are revoked immediately, but desired state stays for
		// explicit re-enrollment. Scope/ID rebinding is never allowed on reload.
		present := map[string]bool{}
		for _, p := range cfg.Targets {
			present[p.ID] = true
		}
		for _, t := range st.Targets {
			if !present[t.ID] && !t.Revoked {
				if err := controlTarget(t, "revoke"); err != nil {
					return err
				}
				s.audit(st, "bootstrap", "revoke", t.Scope, t.ID)
			}
		}
		for _, p := range cfg.Targets {
			old := st.Targets[p.ID]
			if old != nil && old.Scope != p.Scope {
				return errors.New("target attachment cannot be rebound")
			}
			if old == nil {
				old = &TargetState{ID: p.ID, Scope: p.Scope}
				st.Targets[p.ID] = old
				s.audit(st, "bootstrap", "enroll", p.Scope, p.ID)
			}
			old.TokenHash = firewallstate.Digest(p.Token)
		}
		for _, t := range st.Targets {
			if t.TokenHash != "" {
				if _, exists := s.enrolled[t.TokenHash]; exists {
					return errors.New("persisted token binding cannot be reused")
				}
				s.enrolled[t.TokenHash] = Enrollment{ID: t.ID, Scope: t.Scope}
			}
		}
		s.autoMaintain(st, nil, time.Now())
		return validate(st, cfg.AllowEffects)
	})
	if err != nil {
		_ = d.Close()
		return nil, err
	}
	return s, nil
}
func (s *Service) Close() error { s.mu.Lock(); defer s.mu.Unlock(); return s.disk.Close() }
func (s *Service) Backup(ctx context.Context, path string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.disk.Backup(ctx, path)
}

func (s *Service) transaction(ctx context.Context, fn func(*snapshot) error) error {
	return s.transactionMode(ctx, true, fn)
}
func (s *Service) transactionMode(ctx context.Context, write bool, fn func(*snapshot) error) error {
	tx, err := s.disk.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if s.disk.IsPostgres() {
		if err = s.loadArtifactsFrom(ctx, tx); err != nil {
			return err
		}
	}
	st := snapshot{Version: 1, Targets: map[string]*TargetState{}, Revisions: map[string]revision{}, Jobs: map[string]*Job{}}
	var raw []byte
	var size int
	err = tx.QueryRowContext(ctx, `SELECT length(snapshot) FROM fleet WHERE id=1`).Scan(&size)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if size > MaxSnapshotBytes {
		return errors.New("persisted fleet exceeds limit")
	}
	err = tx.QueryRowContext(ctx, `SELECT snapshot FROM fleet WHERE id=1`).Scan(&raw)
	if err == nil {
		if len(raw) > MaxSnapshotBytes {
			return errors.New("persisted fleet exceeds limit")
		}
		if err = firewallstate.Decode(raw, &st); err != nil {
			return err
		}
	} else if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	for key, r := range st.Revisions {
		a, ok := s.artifacts[key]
		if !ok || a.Scope != r.Scope || a.Revision != r.Revision || len(r.Bundle) > 0 {
			return errors.New("snapshot artifact reference invalid")
		}
		r.Bundle = a.Bundle
		st.Revisions[key] = r
	}
	if len(st.Revisions) != len(s.artifacts) {
		return errors.New("orphaned fleet artifacts")
	}
	original := raw
	if err = fn(&st); err != nil {
		return err
	}
	if !write {
		return nil
	}
	// Artifacts are immutable and separate from frequently updated desired/ack
	// metadata, so a heartbeat never rewrites up to 64 MiB of policy bundles.
	persisted := st
	persisted.Revisions = make(map[string]revision, len(st.Revisions))
	for key, r := range st.Revisions {
		if _, ok := s.artifacts[key]; !ok {
			if _, err = tx.ExecContext(ctx, `INSERT INTO artifacts VALUES(?,?,?,?,?)`, key, r.Scope.Tenant, r.Scope.App, r.Revision, []byte(r.Bundle)); err != nil {
				return err
			}
		}
		r.Bundle = nil
		persisted.Revisions[key] = r
	}
	raw, err = json.Marshal(persisted)
	if err != nil {
		return err
	}
	if len(raw) > MaxSnapshotBytes {
		return firewallstate.Fail(503, "fleet metadata capacity exhausted")
	}
	if bytes.Equal(raw, original) {
		return nil
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO fleet VALUES(1,?) ON CONFLICT(id) DO UPDATE SET snapshot=excluded.snapshot`, raw); err != nil {
		return err
	}
	if err = tx.Commit(); err != nil {
		return err
	}
	s.artifacts = st.Revisions
	return nil
}

func (s *Service) loadArtifacts() error {
	return s.loadArtifactsFrom(context.Background(), s.disk.DB)
}

type artifactQuerier interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}

func (s *Service) loadArtifactsFrom(ctx context.Context, q artifactQuerier) error {
	var count, bad int
	if err := q.QueryRowContext(ctx, `SELECT count(*),coalesce(sum(CASE WHEN length(bundle)>1048576 OR length(key)>324 OR length(tenant)>128 OR length(app)>128 OR length(revision)!=64 THEN 1 ELSE 0 END),0) FROM artifacts`).Scan(&count, &bad); err != nil {
		return err
	}
	if count > MaxRevisions || bad > 0 {
		return errors.New("persisted artifact bounds exceeded")
	}
	rows, err := q.QueryContext(ctx, `SELECT key,tenant,app,revision,bundle FROM artifacts`)
	if err != nil {
		return err
	}
	defer rows.Close()
	artifacts := make(map[string]revision, count)
	for rows.Next() {
		var key string
		var r revision
		if err = rows.Scan(&key, &r.Scope.Tenant, &r.Scope.App, &r.Revision, &r.Bundle); err != nil {
			return err
		}
		artifacts[key] = r
	}
	if err = rows.Err(); err != nil {
		return err
	}
	s.artifacts = artifacts
	return nil
}

func validate(st *snapshot, allowEffects bool) error {
	if st.Version != 1 || st.Targets == nil || st.Revisions == nil || st.Jobs == nil || len(st.Targets) > MaxTargets || len(st.Revisions) > MaxRevisions || len(st.Jobs) > MaxJobs || len(st.Audit) > MaxAudit || st.AuditSeq < 0 {
		return errors.New("invalid fleet snapshot bounds/version")
	}
	for key, r := range st.Revisions {
		c, raw, err := compileAdmitted(r.Bundle, allowEffects)
		if err != nil || !r.Scope.Valid() || c == nil || c.Revision() != r.Revision || key != revisionKey(r.Scope, r.Revision) || string(raw) != string(r.Bundle) {
			return errors.New("persisted bundle digest/canonical validation failed")
		}
	}
	for id, t := range st.Targets {
		if t == nil || id != t.ID || !firewallstate.ValidID(id) || !t.Scope.Valid() || t.Generation < 0 || t.ObservedGeneration < 0 || t.ObservedGeneration > t.Generation || len(t.Error) > 512 {
			return errors.New("invalid persisted target")
		}
		if t.Revoked && !t.Draining || t.ObservedRevoked && !t.ObservedDraining || t.Generation == 0 && t.DesiredRevision != "" || t.Generation > 0 && t.DesiredRevision == "" && !t.Draining {
			return errors.New("invalid desired generation")
		}
		for _, rev := range []string{t.DesiredRevision, t.PreviousRevision, t.ObservedRevision} {
			if rev != "" {
				if _, ok := st.Revisions[revisionKey(t.Scope, rev)]; !ok {
					return errors.New("missing target revision")
				}
			}
		}
		if t.ObservedGeneration == 0 && (t.ObservedRevision != "" || t.ObservedDraining || t.ObservedRevoked) || t.ObservedGeneration > 0 && t.ObservedRevision == "" && !t.ObservedDraining || t.ObservedGeneration == t.Generation && t.Generation > 0 && (t.ObservedRevision != t.DesiredRevision || t.ObservedDraining != t.Draining || t.ObservedRevoked != t.Revoked) {
			return errors.New("invalid observed generation")
		}
	}
	for id, j := range st.Jobs {
		if j == nil || id != j.ID || !firewallstate.ValidID(id) || !j.Scope.Valid() || len(j.Targets) < 1 || len(j.Targets) > MaxTargets || j.Deadline.IsZero() || j.Expected == nil || j.Previous == nil || j.Applied == nil {
			return errors.New("invalid persisted job")
		}
		if _, ok := st.Revisions[revisionKey(j.Scope, j.Revision)]; !ok {
			return errors.New("missing job revision")
		}
		if len(j.Failure) > 256 || !slices.Contains([]string{"staged", "canary", "active", "rolledback", "rollback_blocked"}, j.Phase) {
			return errors.New("invalid persisted job phase")
		}
		if len(j.Expected) != len(j.Targets) || len(j.Previous) != len(j.Targets) || len(j.Applied) > len(j.Targets) || len(j.Canary) > len(j.Targets) {
			return errors.New("invalid job map bounds")
		}
		seen := map[string]bool{}
		for _, id := range j.Targets {
			t := st.Targets[id]
			expected, hasExpected := j.Expected[id]
			_, hasPrevious := j.Previous[id]
			if t == nil || t.Scope != j.Scope || seen[id] || !hasExpected || !hasPrevious || expected < 0 || expected > t.Generation {
				return errors.New("invalid job target")
			}
			seen[id] = true
			if j.RollbackOnFailure && j.Previous[id] == "" {
				return errors.New("guarded job missing initialized rollback revision")
			}
			if rev := j.Previous[id]; rev != "" {
				if _, ok := st.Revisions[revisionKey(j.Scope, rev)]; !ok {
					return errors.New("missing rollback revision")
				}
			}
		}
		canaries := map[string]bool{}
		for _, id := range j.Canary {
			if !seen[id] || canaries[id] {
				return errors.New("invalid canary")
			}
			canaries[id] = true
		}
		for id, g := range j.Applied {
			if !seen[id] || g < 1 || g > st.Targets[id].Generation || g <= j.Expected[id] {
				return errors.New("invalid applied generation")
			}
		}
		want := len(j.Targets)
		if j.Phase == "staged" {
			want = 0
		}
		if j.Phase == "canary" {
			want = len(j.Canary)
			if want == 0 {
				return errors.New("empty canary phase")
			}
		}
		if j.Phase == "rolledback" || j.Phase == "rollback_blocked" {
			if len(j.Applied) == 0 {
				return errors.New("empty rollback")
			}
		} else if len(j.Applied) != want {
			return errors.New("job phase/applied mismatch")
		}
	}
	var last int64
	for _, a := range st.Audit {
		if a.ID <= last || a.ID > st.AuditSeq || a.Time.IsZero() || !a.Scope.Valid() || !firewallstate.ValidID(a.Actor) || len(a.Operation) > 32 || len(a.Object) > 256 {
			return errors.New("invalid audit history")
		}
		last = a.ID
	}
	return nil
}

func (s *Service) admin(token string, requested Scope) (string, Scope, error) {
	if firewallstate.MatchToken(token, s.cfg.Token) {
		if !requested.Valid() {
			return "", Scope{}, firewallstate.Fail(400, "tenant/app scope required")
		}
		return "administrator", requested, nil
	}
	for _, p := range s.cfg.Identities {
		if firewallstate.MatchToken(token, p.Token) {
			if requested != (Scope{}) && requested != p.Scope {
				return "", Scope{}, firewallstate.Fail(403, "foreign scope")
			}
			return p.ID, p.Scope, nil
		}
	}
	return "", Scope{}, firewallstate.Fail(401, "administrative bearer required")
}
func (s *Service) target(token string) (Enrollment, error) {
	if p, ok := s.enrolled[firewallstate.Digest(token)]; ok && token != "" {
		return p, nil
	}
	return Enrollment{}, firewallstate.Fail(401, "enrolled target bearer required")
}
func (s *Service) audit(st *snapshot, actor, op string, scope Scope, object string) {
	st.AuditSeq++
	st.Audit = append(st.Audit, Audit{st.AuditSeq, time.Now().UTC(), actor, op, scope, object})
	if len(st.Audit) > MaxAudit {
		st.Audit = st.Audit[len(st.Audit)-MaxAudit:]
	}
}

// Execute is the authenticated administrative REST/MCP boundary. Target tokens
// cannot invoke this API; HTTP desired/ack derive their attachment from enrollment.
func (s *Service) Execute(ctx context.Context, token, op string, r Request) (any, error) {
	actor, scope, err := s.admin(token, r.Scope)
	if err != nil {
		return nil, err
	}
	if len(r.Bundle) > MaxArtifactBytes || len(r.Targets) > MaxTargets || len(r.Canary) > MaxTargets || len(r.Expected) > MaxTargets {
		return nil, firewallstate.Fail(413, "request bounds exceeded")
	}
	select {
	case s.slots <- struct{}{}:
		defer func() { <-s.slots }()
	default:
		return nil, firewallstate.Fail(429, "controller overloaded")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if op != "audit" && op != "capabilities" {
		if _, err = s.maintainLocked(ctx, &scope); err != nil {
			return nil, err
		}
	}
	var out any
	err = s.transactionMode(ctx, op != "status" && op != "audit" && op != "capabilities", func(st *snapshot) error {
		switch op {
		case "capabilities":
			out = map[string]any{"allow_effects": s.cfg.AllowEffects, "rollback_on_failure": s.cfg.RollbackOnFailure, "effects_execution": "external scope-authorized broker; admission grants no execution rights", "coordination": s.disk.Coordination(), "max_targets": MaxTargets, "max_revisions": MaxRevisions, "max_jobs": MaxJobs, "max_artifact_bytes": MaxArtifactBytes}
		case "status":
			result := Status{Targets: map[string]*TargetState{}, Jobs: []*Job{}, Coordination: s.disk.Coordination()}
			for id, t := range st.Targets {
				if t.Scope == scope {
					cp := *t
					cp.TokenHash = ""
					result.Targets[id] = &cp
				}
			}
			for _, j := range st.Jobs {
				if j.Scope == scope {
					result.Jobs = append(result.Jobs, j)
				}
			}
			out = result
		case "audit":
			result := []Audit{}
			for _, a := range st.Audit {
				if a.Scope == scope {
					result = append(result, a)
				}
			}
			out = result
		case "stage":
			c, raw, e := compileAdmitted([]byte(r.Bundle), s.cfg.AllowEffects)
			if e != nil {
				return e
			}
			key := revisionKey(scope, c.Revision())
			if _, ok := st.Revisions[key]; !ok {
				if len(st.Revisions) >= MaxRevisions {
					return firewallstate.Fail(409, "revision capacity exhausted")
				}
				st.Revisions[key] = revision{scope, c.Revision(), raw}
				s.audit(st, actor, op, scope, c.Revision())
			}
			out = map[string]string{"revision": c.Revision()}
		case "rollout":
			if !firewallstate.ValidID(r.ID) || len(r.Targets) == 0 || len(r.Expected) != len(r.Targets) || !r.Deadline.After(time.Now()) || r.Deadline.After(time.Now().Add(24*time.Hour)) {
				return firewallstate.Fail(400, "rollout requires ID, targets, expected generations, deadline within 24h")
			}
			if _, ok := st.Revisions[revisionKey(scope, r.Revision)]; !ok {
				return firewallstate.Fail(404, "revision not staged in scope")
			}
			if st.Jobs[r.ID] != nil {
				return firewallstate.Fail(409, "job ID exists")
			}
			if len(st.Jobs) >= MaxJobs {
				return firewallstate.Fail(409, "job capacity exhausted")
			}
			j := &Job{ID: r.ID, Scope: scope, Revision: r.Revision, Targets: r.Targets, Canary: r.Canary, Expected: r.Expected, Previous: map[string]string{}, Applied: map[string]int64{}, Phase: "staged", Deadline: r.Deadline, RollbackOnFailure: r.RollbackOnFailure || s.cfg.RollbackOnFailure}
			seen := map[string]bool{}
			for _, id := range r.Targets {
				t := st.Targets[id]
				expected, ok := r.Expected[id]
				if t == nil || t.Scope != scope || t.Draining || t.Revoked || seen[id] || !ok || t.Generation != expected {
					return firewallstate.Fail(409, "target absent, foreign, duplicate or generation conflict")
				}
				seen[id] = true
				j.Previous[id] = t.DesiredRevision
				if j.RollbackOnFailure && t.DesiredRevision == "" {
					return firewallstate.Fail(409, "automatic rollback requires initialized previous revisions")
				}
			}
			seenCanary := map[string]bool{}
			for _, id := range r.Canary {
				if !seen[id] || seenCanary[id] {
					return firewallstate.Fail(400, "invalid canary subset")
				}
				seenCanary[id] = true
			}
			st.Jobs[j.ID] = j
			s.audit(st, actor, op, scope, j.ID)
			out = j
		case "activate", "promote", "rollback":
			j := st.Jobs[r.ID]
			if j == nil || j.Scope != scope {
				return firewallstate.Fail(404, "job not found")
			}
			if r.ExpectedPhase == "" || j.Phase != r.ExpectedPhase {
				return firewallstate.Fail(409, "job phase CAS conflict")
			}
			if _, _, err := compileAdmitted(st.Revisions[revisionKey(scope, j.Revision)].Bundle, s.cfg.AllowEffects); err != nil {
				return err
			}
			if op != "rollback" && !time.Now().Before(j.Deadline) {
				return firewallstate.Fail(409, "rollout deadline exceeded; last known policy remains")
			}
			if op == "activate" && j.Phase != "staged" || op == "promote" && j.Phase != "canary" || op == "rollback" && (j.Phase != "canary" && j.Phase != "active") {
				return firewallstate.Fail(409, "invalid rollout transition")
			}
			if op == "promote" {
				for _, id := range j.Canary {
					t := st.Targets[id]
					if t.Generation != j.Applied[id] || t.ObservedGeneration != j.Applied[id] || t.ObservedRevision != j.Revision || t.Error != "" {
						return firewallstate.Fail(409, "canary not converged")
					}
				}
			}
			selected := j.Targets
			if op == "activate" && len(j.Canary) > 0 {
				selected = j.Canary
			}
			for _, id := range selected {
				t := st.Targets[id]
				if t.Draining || t.Revoked {
					return firewallstate.Fail(409, "target is draining or revoked")
				}
				if op == "promote" && slices.Contains(j.Canary, id) {
					continue
				}
				if op == "rollback" {
					if _, ok := j.Applied[id]; !ok {
						continue
					}
					if j.Previous[id] == "" {
						return firewallstate.Fail(409, "no initialized rollback revision for target")
					}
					if _, _, err := compileAdmitted(st.Revisions[revisionKey(scope, j.Previous[id])].Bundle, s.cfg.AllowEffects); err != nil {
						return err
					}
					if t.Generation != j.Applied[id] || t.DesiredRevision != j.Revision {
						return firewallstate.Fail(409, "rollback generation conflict")
					}
				} else if t.Generation != j.Expected[id] {
					return firewallstate.Fail(409, "target generation CAS conflict")
				}
				if t.Generation == math.MaxInt64 {
					return firewallstate.Fail(409, "generation exhausted")
				}
			}
			for _, id := range selected {
				t := st.Targets[id]
				if op == "promote" && slices.Contains(j.Canary, id) {
					continue
				}
				rev := j.Revision
				if op == "rollback" {
					if _, ok := j.Applied[id]; !ok {
						continue
					}
					rev = j.Previous[id]
				}
				t.PreviousRevision = t.DesiredRevision
				t.DesiredRevision = rev
				t.Generation++
				t.Deadline = j.Deadline
				if op == "rollback" {
					t.Deadline = time.Now().UTC().Add(24 * time.Hour)
				}
				t.Error = ""
				j.Applied[id] = t.Generation
			}
			j.Phase = "active"
			if op == "activate" && len(j.Canary) > 0 {
				j.Phase = "canary"
			}
			if op == "rollback" {
				j.Phase = "rolledback"
			}
			s.audit(st, actor, op, scope, j.ID)
			out = j
		case "drain", "revoke", "resume":
			if len(r.Targets) == 0 || len(r.Expected) != len(r.Targets) {
				return firewallstate.Fail(400, "targets and expected generations required")
			}
			seen := map[string]bool{}
			for _, id := range r.Targets {
				t := st.Targets[id]
				g, ok := r.Expected[id]
				if t == nil || t.Scope != scope || seen[id] || !ok || g != t.Generation {
					return firewallstate.Fail(409, "target scope or generation conflict")
				}
				seen[id] = true
				if t.Generation == math.MaxInt64 {
					return firewallstate.Fail(409, "generation exhausted")
				}
				if op == "resume" && t.DesiredRevision == "" {
					return firewallstate.Fail(409, "target has no initialized revision")
				}
			}
			result := map[string]int64{}
			for _, id := range r.Targets {
				t := st.Targets[id]
				if err := controlTarget(t, op); err != nil {
					return err
				}
				result[id] = t.Generation
				s.audit(st, actor, op, scope, id)
			}
			out = result
		default:
			return firewallstate.Fail(404, "unknown fleet operation")
		}
		return nil
	})
	return out, err
}

func (s *Service) Desired(ctx context.Context, token string) (Desired, error) {
	p, err := s.target(token)
	if err != nil {
		return Desired{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err = s.maintainLocked(ctx, &p.Scope); err != nil {
		return Desired{}, err
	}
	var out Desired
	err = s.transactionMode(ctx, false, func(st *snapshot) error {
		t := st.Targets[p.ID]
		if t == nil || t.Scope != p.Scope || t.TokenHash != firewallstate.Digest(token) {
			return firewallstate.Fail(403, "enrollment revoked")
		}
		if t.Generation == 0 {
			return firewallstate.Fail(503, "target has no desired policy")
		}
		out = Desired{Version: 1, TargetID: t.ID, Scope: t.Scope, Generation: t.Generation, Revision: t.DesiredRevision, Deadline: t.Deadline, Draining: t.Draining, Revoked: t.Revoked}
		if !t.Draining {
			rev := st.Revisions[revisionKey(t.Scope, t.DesiredRevision)]
			out.Hash = firewallstate.Digest(string(rev.Bundle))
			out.Bundle = append(json.RawMessage(nil), rev.Bundle...)
		}
		return nil
	})
	return out, err
}
func (s *Service) Acknowledge(ctx context.Context, token string, a Ack) error {
	p, err := s.target(token)
	if err != nil {
		return err
	}
	if a.Generation < 1 || len(a.Error) > 512 || len(a.Revision) > 64 {
		return firewallstate.Fail(400, "invalid acknowledgment")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.transaction(ctx, func(st *snapshot) error {
		t := st.Targets[p.ID]
		if t == nil || t.Scope != p.Scope || t.TokenHash != firewallstate.Digest(token) {
			return firewallstate.Fail(403, "enrollment revoked")
		}
		if a.Generation != t.Generation || a.Revision != t.DesiredRevision || a.Draining != t.Draining || a.Revoked != t.Revoked {
			return firewallstate.Fail(409, "stale or foreign acknowledgment")
		}
		t.LastSeen = time.Now().UTC()
		t.Error = a.Error
		if a.Error == "" {
			t.ObservedRevision = a.Revision
			t.ObservedGeneration = a.Generation
			t.ObservedDraining = a.Draining
			t.ObservedRevoked = a.Revoked
		}
		s.audit(st, p.ID, "ack", t.Scope, fmt.Sprintf("%s:%d", t.ID, a.Generation))
		s.autoMaintain(st, &p.Scope, time.Now())
		return nil
	})
}
