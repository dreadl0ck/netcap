package firewallfleet

import (
	"context"
	"math"
	"slices"
	"time"

	"github.com/dreadl0ck/netcap/internal/firewallauth"
	"github.com/dreadl0ck/netcap/internal/firewallstate"
)

type MaintenanceResult struct {
	RolledBack []string `json:"rolled_back"`
	Blocked    []string `json:"blocked"`
}

// Maintain checks at most MaxJobs, with no owned goroutine or timer. The trusted
// main integration should call it periodically even when transports are idle.
// Scoped status, desired polling, and acknowledgments also drive maintenance.
func (s *Service) Maintain(ctx context.Context) (MaintenanceResult, error) {
	if s.cfg.Auth != nil && firewallauth.Require(ctx, firewallauth.Rollback, firewallauth.Scope{Tenant: "*", App: "*", Environment: s.cfg.Environment, Target: "*"}) != nil {
		return MaintenanceResult{}, firewallstate.Fail(403, "fleet maintenance grant required")
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.maintainLocked(ctx, nil)
}
func (s *Service) maintainLocked(ctx context.Context, scope *Scope) (MaintenanceResult, error) {
	var result MaintenanceResult
	err := s.transaction(ctx, func(st *snapshot) error { result = s.autoMaintain(st, scope, time.Now()); return nil })
	return result, err
}

func (s *Service) autoMaintain(st *snapshot, scope *Scope, now time.Time) MaintenanceResult {
	result := MaintenanceResult{RolledBack: []string{}, Blocked: []string{}}
	ids := make([]string, 0, len(st.Jobs))
	for id := range st.Jobs {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	for _, id := range ids {
		j := st.Jobs[id]
		if !j.RollbackOnFailure || scope != nil && j.Scope != *scope || j.Phase != "canary" && j.Phase != "active" {
			continue
		}
		failed, converged := false, true
		for target, g := range j.Applied {
			t := st.Targets[target]
			if t.Generation != g || t.DesiredRevision != j.Revision || t.Draining || t.Revoked {
				converged = false
				continue
			}
			if t.Error != "" {
				failed = true
			}
			if t.ObservedGeneration != g || t.ObservedRevision != j.Revision || t.Error != "" {
				converged = false
			}
		}
		reason := "health acknowledgment failed"
		if !failed {
			if now.Before(j.Deadline) || j.Phase == "active" && converged {
				continue
			}
			reason = "rollout deadline missed"
		}
		blocked := false
		for target, g := range j.Applied {
			t := st.Targets[target]
			if t.Scope != j.Scope || t.Generation != g || t.DesiredRevision != j.Revision || t.Generation == math.MaxInt64 || t.Draining || t.Revoked || j.Previous[target] == "" {
				blocked = true
				break
			}
		}
		j.Failure = reason
		if blocked {
			j.Phase = "rollback_blocked"
			j.Failure += "; target generation/control conflict"
			s.audit(st, "controller", "auto_rollback_blocked", j.Scope, j.ID)
			result.Blocked = append(result.Blocked, j.ID)
			continue
		}
		for target := range j.Applied {
			t := st.Targets[target]
			t.PreviousRevision = t.DesiredRevision
			t.DesiredRevision = j.Previous[target]
			t.Generation++
			t.Deadline = now.UTC().Add(24 * time.Hour)
			t.Error = ""
			j.Applied[target] = t.Generation
		}
		j.Phase = "rolledback"
		s.audit(st, "controller", "auto_rollback", j.Scope, j.ID)
		result.RolledBack = append(result.RolledBack, j.ID)
	}
	return result
}

func controlTarget(t *TargetState, operation string) error {
	if t.Generation == math.MaxInt64 {
		return firewallstate.Fail(409, "generation exhausted")
	}
	t.Generation++
	t.Deadline = time.Time{}
	t.Error = ""
	switch operation {
	case "drain":
		t.Draining = true
	case "revoke":
		t.Draining = true
		t.Revoked = true
	case "resume":
		t.Draining = false
		t.Revoked = false
	}
	return nil
}
