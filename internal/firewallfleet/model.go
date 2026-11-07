// Package firewallfleet distributes immutable policy revisions to explicitly
// enrolled targets. Generations are per-target CAS values, not a globally atomic
// deployment. SQLite is fenced per StateDir; PostgreSQL coordinates replicas.
package firewallfleet

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/dreadl0ck/netcap/internal/firewallauth"
	"github.com/dreadl0ck/netcap/internal/firewallstate"
	"github.com/dreadl0ck/netcap/internal/policy"
)

const (
	MaxTargets       = 100
	MaxRevisions     = 64
	MaxJobs          = 128
	MaxAudit         = 2048
	MaxArtifactBytes = 1 << 20
	MaxRequestBytes  = 2 << 20
	MaxSnapshotBytes = 16 << 20
)

type Scope = firewallstate.Scope
type Identity struct {
	Role  string `json:"role,omitempty"`
	ID    string
	Token string
	Scope Scope
}

// Enrollment is bootstrap-only. The controller binds token to ID/tenant/app;
// agents cannot enroll themselves or provide their own attachment scope.
type Enrollment struct {
	ID    string
	Token string
	Scope Scope
}
type Config struct {
	Approvals   *firewallauth.Approvals
	Auth        *firewallauth.Authority
	Environment string
	Origin      string
	// AuditRequired refuses mutations when the retained audit is full. Export
	// does not acknowledge deletion; retention remains an explicit operator choice.
	AuditRequired       bool
	AuditRetention      time.Duration
	AuditMaxRecords     int
	JobReceiptRetention time.Duration
	StateDir            string
	DatabaseURL         string
	DatabaseNamespace   string
	Token               string
	Identities          []Identity
	Targets             []Enrollment
	AllowEffects        bool
	RollbackOnFailure   bool
}
type Target interface {
	Policy() *policy.Compiled
	SetPolicy(*policy.Compiled)
}
type TargetState struct {
	ID                 string    `json:"id"`
	Scope              Scope     `json:"scope"`
	TokenHash          string    `json:"token_hash,omitempty"`
	DesiredRevision    string    `json:"desired_revision"`
	PreviousRevision   string    `json:"previous_revision"`
	Generation         int64     `json:"generation"`
	ObservedRevision   string    `json:"observed_revision"`
	ObservedGeneration int64     `json:"observed_generation"`
	LastSeen           time.Time `json:"last_seen"`
	Error              string    `json:"error,omitempty"`
	Deadline           time.Time `json:"deadline"`
	Draining           bool      `json:"draining,omitempty"`
	Revoked            bool      `json:"revoked,omitempty"`
	ObservedDraining   bool      `json:"observed_draining,omitempty"`
	ObservedRevoked    bool      `json:"observed_revoked,omitempty"`
}
type Desired struct {
	Version    int             `json:"version"`
	TargetID   string          `json:"target_id"`
	Scope      Scope           `json:"scope"`
	Generation int64           `json:"generation"`
	Revision   string          `json:"revision"`
	Hash       string          `json:"hash"`
	Bundle     json.RawMessage `json:"bundle,omitempty"`
	Deadline   time.Time       `json:"deadline"`
	Draining   bool            `json:"draining,omitempty"`
	Revoked    bool            `json:"revoked,omitempty"`
}
type Ack struct {
	Revision   string `json:"revision"`
	Generation int64  `json:"generation"`
	Error      string `json:"error,omitempty"`
	Draining   bool   `json:"draining,omitempty"`
	Revoked    bool   `json:"revoked,omitempty"`
}
type Job struct {
	ID                string            `json:"id"`
	Scope             Scope             `json:"scope"`
	Revision          string            `json:"revision"`
	Targets           []string          `json:"targets"`
	Canary            []string          `json:"canary"`
	Expected          map[string]int64  `json:"expected"`
	Previous          map[string]string `json:"previous"`
	Applied           map[string]int64  `json:"applied"`
	Phase             string            `json:"phase"`
	Deadline          time.Time         `json:"deadline"`
	RollbackOnFailure bool              `json:"rollback_on_failure,omitempty"`
	Failure           string            `json:"failure,omitempty"`
}
type Audit struct {
	ID                int64             `json:"id"`
	Time              time.Time         `json:"time"`
	Actor             string            `json:"actor"`
	Operation         string            `json:"operation"`
	Scope             Scope             `json:"scope"`
	Object            string            `json:"object"`
	Grant             string            `json:"grant,omitempty"`
	Outcome           string            `json:"outcome,omitempty"`
	Reason            string            `json:"reason,omitempty"`
	Revision          string            `json:"revision,omitempty"`
	PreviousRevision  string            `json:"previous_revision,omitempty"`
	Generation        int64             `json:"generation,omitempty"`
	Correlation       string            `json:"correlation,omitempty"`
	Targets           []string          `json:"targets,omitempty"`
	PreviousRevisions map[string]string `json:"previous_revisions,omitempty"`
}
type Request struct {
	Approval          *firewallauth.ApprovalRequest `json:"approval,omitempty"`
	Receipt           string                        `json:"receipt,omitempty"`
	Revisions         []string                      `json:"revisions,omitempty"`
	Jobs              []string                      `json:"jobs,omitempty"`
	Receipts          []string                      `json:"receipts,omitempty"`
	ExpectedPlan      string                        `json:"expected_plan,omitempty"`
	After             int64                         `json:"after,omitempty"`
	Limit             int                           `json:"limit,omitempty"`
	Scope             Scope                         `json:"scope"`
	Bundle            string                        `json:"bundle,omitempty"`
	Revision          string                        `json:"revision,omitempty"`
	ID                string                        `json:"id,omitempty"`
	Targets           []string                      `json:"targets,omitempty"`
	Canary            []string                      `json:"canary,omitempty"`
	Expected          map[string]int64              `json:"expected,omitempty"`
	Deadline          time.Time                     `json:"deadline,omitempty"`
	ExpectedPhase     string                        `json:"expected_phase,omitempty"`
	RollbackOnFailure bool                          `json:"rollback_on_failure,omitempty"`
}
type revision struct {
	Scope    Scope           `json:"scope"`
	Revision string          `json:"revision"`
	Bundle   json.RawMessage `json:"bundle,omitempty"`
}

func ApprovalDigest(operation string, r Request) string {
	r.Receipt = ""
	r.Approval = nil
	return firewallauth.Digest(struct {
		Operation string  `json:"operation"`
		Request   Request `json:"request"`
	}{operation, r})
}

type snapshot struct {
	AuditOverflow bool                    `json:"-"`
	ArchivedJobs  map[string]JobReceipt   `json:"archived_jobs,omitempty"`
	Version       int                     `json:"version"`
	Targets       map[string]*TargetState `json:"targets"`
	Revisions     map[string]revision     `json:"revisions"`
	Jobs          map[string]*Job         `json:"jobs"`
	Audit         []Audit                 `json:"audit"`
	AuditSeq      int64                   `json:"audit_seq"`
}

func revisionKey(s Scope, rev string) string { return s.Tenant + "/" + s.App + "/" + rev }
func compile(raw []byte) (*policy.Compiled, []byte, error) {
	return compileAdmitted(raw, false)
}
func compileAdmitted(raw []byte, allowEffects bool) (*policy.Compiled, []byte, error) {
	if len(raw) == 0 || len(raw) > MaxArtifactBytes {
		return nil, nil, firewallstate.Fail(400, "bundle exceeds artifact limit")
	}
	b, err := policy.Parse(raw)
	if err != nil {
		return nil, nil, firewallstate.Fail(400, "invalid bundle: "+err.Error())
	}
	c, err := policy.CompileWithOptions(b, policy.CompileOptions{AllowEffects: allowEffects})
	if err != nil {
		return nil, nil, firewallstate.Fail(400, "invalid policy: "+err.Error())
	}
	canonical, err := json.Marshal(c.Bundle())
	if err != nil {
		return nil, nil, err
	}
	if len(canonical) > MaxArtifactBytes {
		return nil, nil, errors.New("canonical bundle too large")
	}
	return c, canonical, nil
}

// WaitConverged observes acknowledgements only; a transport ack cannot prove
// every in-flight request has finished under the old revision.
func (s *Service) WaitConverged(ctx context.Context, token string, scope Scope, jobID string) error {
	t := time.NewTicker(100 * time.Millisecond)
	defer t.Stop()
	for {
		out, err := s.Execute(ctx, token, "status", Request{Scope: scope})
		if err != nil {
			return err
		}
		status := out.(Status)
		var job *Job
		for _, j := range status.Jobs {
			if j.ID == jobID {
				job = j
			}
		}
		if job == nil {
			return firewallstate.Fail(404, "job not found")
		}
		if job.Phase != "active" {
			return firewallstate.Fail(409, "job is not fully activated")
		}
		ok := true
		for id, gen := range job.Applied {
			st := status.Targets[id]
			if st == nil || st.Draining || st.Revoked || st.Generation != gen || st.ObservedGeneration != gen || st.ObservedRevision != job.Revision || st.Error != "" {
				ok = false
			}
		}
		if ok {
			return nil
		}
		if time.Now().After(job.Deadline) {
			return context.DeadlineExceeded
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
		}
	}
}

type Status struct {
	Targets      map[string]*TargetState `json:"targets"`
	Jobs         []*Job                  `json:"jobs"`
	Coordination string                  `json:"coordination"`
}
