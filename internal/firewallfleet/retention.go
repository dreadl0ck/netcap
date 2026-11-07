package firewallfleet

import (
	"encoding/json"
	"slices"
	"time"

	"github.com/dreadl0ck/netcap/internal/firewallstate"
)

const OperationsVersion = 1
const MaxArchivedJobs = 4096

type JobReceipt struct {
	Scope   Scope     `json:"scope"`
	Expires time.Time `json:"expires"`
}

func validRevisionDigest(rev string) bool {
	if len(rev) != 64 {
		return false
	}
	for _, c := range rev {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// RetentionReport fences all snapshot fields, including acknowledgements and
// enrollments, at the transaction's authoritative read.
type RetentionReport struct {
	Version          int                  `json:"version"`
	Plan             string               `json:"plan"`
	Revisions        []string             `json:"revisions"`
	Jobs             []string             `json:"jobs"`
	Receipts         []string             `json:"receipts"`
	ReceiptInventory map[string]time.Time `json:"receipt_inventory"`
	Protected        []string             `json:"protected"`
}

func retention(st *snapshot, scope Scope, r Request) RetentionReport {
	raw, _ := json.Marshal(struct {
		State                     *snapshot
		Scope                     Scope
		Revisions, Jobs, Receipts []string
	}{st, scope, r.Revisions, r.Jobs, r.Receipts})
	out := RetentionReport{Version: OperationsVersion, Plan: firewallstate.Digest(string(raw)), Revisions: []string{}, Jobs: []string{}, Receipts: []string{}, Protected: []string{}}
	out.ReceiptInventory = map[string]time.Time{}
	for id, receipt := range st.ArchivedJobs {
		if receipt.Scope == scope {
			out.ReceiptInventory[id] = receipt.Expires
		}
	}
	for _, id := range r.Receipts {
		if receipt, ok := st.ArchivedJobs[id]; ok && receipt.Scope == scope {
			if !time.Now().Before(receipt.Expires) {
				out.Receipts = append(out.Receipts, id)
			} else {
				out.Protected = append(out.Protected, "receipt:"+id)
			}
		}
	}
	for _, id := range r.Jobs {
		j := st.Jobs[id]
		if j == nil || j.Scope != scope {
			continue
		}
		safe := j.Phase == "rolledback"
		if j.Phase == "active" {
			safe = true
			for _, target := range j.Targets {
				t := st.Targets[target]
				if t == nil || t.Generation <= j.Applied[target] {
					safe = false
				}
			}
		}
		if safe {
			out.Jobs = append(out.Jobs, id)
		} else {
			out.Protected = append(out.Protected, "job:"+id)
		}
	}
	refs := map[string]bool{}
	protect := func(s Scope, rev string) {
		if rev != "" {
			refs[revisionKey(s, rev)] = true
		}
	}
	for _, t := range st.Targets {
		protect(t.Scope, t.DesiredRevision)
		protect(t.Scope, t.PreviousRevision)
		protect(t.Scope, t.ObservedRevision)
	}
	for id, j := range st.Jobs {
		if slices.Contains(out.Jobs, id) {
			continue
		}
		protect(j.Scope, j.Revision)
		for _, rev := range j.Previous {
			protect(j.Scope, rev)
		}
	}
	for _, rev := range r.Revisions {
		key := revisionKey(scope, rev)
		if _, ok := st.Revisions[key]; !ok {
			continue
		}
		if refs[key] {
			out.Protected = append(out.Protected, "revision:"+rev)
		} else {
			out.Revisions = append(out.Revisions, rev)
		}
	}
	slices.Sort(out.Jobs)
	out.Jobs = slices.Compact(out.Jobs)
	slices.Sort(out.Receipts)
	out.Receipts = slices.Compact(out.Receipts)
	slices.Sort(out.Revisions)
	out.Revisions = slices.Compact(out.Revisions)
	slices.Sort(out.Protected)
	out.Protected = slices.Compact(out.Protected)
	plan, _ := json.Marshal(out)
	out.Plan = firewallstate.Digest(string(plan))
	return out
}

func (s *Service) prune(st *snapshot, actor string, scope Scope, r Request) (RetentionReport, error) {
	out := retention(st, scope, r)
	if r.ExpectedPlan == "" || r.ExpectedPlan != out.Plan {
		return out, firewallstate.Fail(409, "retention plan CAS conflict; preview again")
	}
	if len(st.ArchivedJobs)-len(out.Receipts)+len(out.Jobs) > MaxArchivedJobs {
		return out, firewallstate.Fail(409, "job receipt capacity exhausted; preview expired receipts for pruning")
	}
	if st.ArchivedJobs == nil {
		st.ArchivedJobs = map[string]JobReceipt{}
	}
	for _, id := range out.Receipts {
		s.audit(st, actor, "prune_receipt", scope, id)
		delete(st.ArchivedJobs, id)
	}
	for _, id := range out.Jobs {
		s.audit(st, actor, "archive_job", scope, id)
		delete(st.Jobs, id)
		st.ArchivedJobs[id] = JobReceipt{Scope: scope, Expires: time.Now().UTC().Add(s.cfg.JobReceiptRetention)}
	}
	for _, rev := range out.Revisions {
		delete(st.Revisions, revisionKey(scope, rev))
		s.audit(st, actor, "prune_revision", scope, rev)
	}
	return out, nil
}
