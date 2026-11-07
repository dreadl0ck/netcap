package firewallfleet

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestReceiptRetentionRecoversCapacityAndPreservesIdentity(t *testing.T) {
	s, err := New(fleetConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	old := stage(t, s, "old-receipt", "allow")
	current := stage(t, s, "new-receipt", "deny")
	for i, rev := range []string{old, current} {
		id := fmt.Sprintf("receipt-job-%d", i)
		rollout(t, s, id, rev, map[string]int64{"a": int64(i), "b": int64(i)}, nil)
		execute(t, s, "activate", Request{ID: id, ExpectedPhase: "staged"})
	}
	err = s.transaction(context.Background(), func(st *snapshot) error {
		st.ArchivedJobs = map[string]JobReceipt{}
		for i := range MaxArchivedJobs {
			st.ArchivedJobs[fmt.Sprintf("receipt-%d", i)] = JobReceipt{Scope: scopeA, Expires: time.Now().Add(-time.Hour)}
		}
		st.ArchivedJobs["receipt-0"] = JobReceipt{Scope: scopeA, Expires: time.Now().Add(time.Hour)}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	r := Request{Jobs: []string{"receipt-job-0"}}
	p := execute(t, s, "retention_preview", r).(RetentionReport)
	r.ExpectedPlan = p.Plan
	if _, err = s.Execute(context.Background(), adminToken, "prune", withScope(r)); err == nil {
		t.Fatal("full receipt sink accepted growth")
	}
	r.Receipts = []string{"receipt-0", "receipt-1"}
	p = execute(t, s, "retention_preview", r).(RetentionReport)
	if !slices.Equal(p.Receipts, []string{"receipt-1"}) || !slices.Contains(p.Protected, "receipt:receipt-0") {
		t.Fatalf("receipt retention: %+v", p)
	}
	r.ExpectedPlan = p.Plan
	execute(t, s, "prune", r)
	p = execute(t, s, "retention_preview", Request{}).(RetentionReport)
	if len(p.ReceiptInventory) != MaxArchivedJobs || p.ReceiptInventory["receipt-job-0"].Before(time.Now().Add(29*24*time.Hour)) {
		t.Fatal("new durable identity receipt missing")
	}
	if _, err = s.Execute(context.Background(), adminToken, "rollout", Request{Scope: scopeA, ID: "receipt-job-0", Revision: current, Targets: []string{"a"}, Expected: map[string]int64{"a": 2}, Deadline: time.Now().Add(time.Hour)}); err == nil {
		t.Fatal("pruned job was replayable")
	}
}

func TestRetentionRecoversRevisionAndJobCaps(t *testing.T) {
	s, err := New(fleetConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	var revs []string
	for i := range MaxRevisions {
		revs = append(revs, stage(t, s, fmt.Sprintf("capacity-%d", i), "allow"))
	}
	if _, err = s.Execute(context.Background(), adminToken, "stage", Request{Scope: scopeA, Bundle: `{"version":"1","id":"over-cap","mode":"enforce","default":"allow"}`}); err == nil {
		t.Fatal("revision limit ignored")
	}
	r := Request{Revisions: revs[1:]}
	p := execute(t, s, "retention_preview", r).(RetentionReport)
	r.ExpectedPlan = p.Plan
	execute(t, s, "prune", r)
	stage(t, s, "after-gc", "deny")
	var jobs []string
	for i := range MaxJobs {
		id := fmt.Sprintf("capacity-job-%d", i)
		jobs = append(jobs, id)
		rollout(t, s, id, revs[0], map[string]int64{"a": int64(i), "b": int64(i)}, nil)
		execute(t, s, "activate", Request{ID: id, ExpectedPhase: "staged"})
	}
	request := Request{Scope: scopeA, ID: "after-job-gc", Revision: revs[0], Targets: []string{"a", "b"}, Expected: map[string]int64{"a": MaxJobs, "b": MaxJobs}, Deadline: time.Now().Add(time.Hour)}
	if _, err = s.Execute(context.Background(), adminToken, "rollout", request); err == nil {
		t.Fatal("job limit ignored")
	}
	r = Request{Jobs: jobs, Revisions: []string{revs[0]}}
	p = execute(t, s, "retention_preview", r).(RetentionReport)
	if len(p.Jobs) != MaxJobs-1 || len(p.Revisions) != 0 || !slices.Contains(p.Protected, "job:"+jobs[MaxJobs-1]) {
		t.Fatalf("active job protection: %+v", p)
	}
	r.ExpectedPlan = p.Plan
	execute(t, s, "prune", r)
	execute(t, s, "rollout", request)
}

func TestAuditOptionalBackpressureAndRejectedOutcome(t *testing.T) {
	cfg := fleetConfig(t)
	cfg.AuditMaxRecords = 4
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	for i := range 5 {
		stage(t, s, fmt.Sprintf("audit-overwrite-%d", i), "allow")
	}
	if _, err = s.Execute(context.Background(), adminToken, "activate", Request{Scope: scopeA, ID: "missing-job", ExpectedPhase: "staged"}); err == nil {
		t.Fatal("missing job accepted")
	}
	page := execute(t, s, "audit_export", Request{After: 1}).(AuditPage)
	if len(page.Records) > 4 || !page.Truncated {
		t.Fatalf("unbounded/lost overflow indication: %+v", page)
	}
	a := page.Records[len(page.Records)-1]
	if a.Actor != "administrator" || a.Grant != "operator" || a.Outcome != "rejected" || a.Reason == "" {
		t.Fatalf("missing redacted rejection: %+v", a)
	}
}

func TestRequiredAuditPruneIsAtomic(t *testing.T) {
	cfg := fleetConfig(t)
	cfg.AuditRequired = true
	cfg.AuditMaxRecords = 4
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	rev := stage(t, s, "audit-protected-artifact", "deny")
	r := Request{Scope: scopeA, Revisions: []string{rev}}
	p := execute(t, s, "retention_preview", r).(RetentionReport)
	r.ExpectedPlan = p.Plan
	if _, err = s.Execute(context.Background(), adminToken, "prune", r); err == nil {
		t.Fatal("prune committed without required audit")
	}
	var count int
	if err = s.disk.DB.QueryRow(`SELECT count(*) FROM artifacts`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("prune escaped audit transaction: %d %v", count, err)
	}
	p = execute(t, s, "retention_preview", Request{}).(RetentionReport)
	execute(t, s, "audit_ack", Request{After: 3, ExpectedPlan: p.Plan})
	p = execute(t, s, "retention_preview", r).(RetentionReport)
	r.ExpectedPlan = p.Plan
	execute(t, s, "prune", r)
}

func withScope(r Request) Request { r.Scope = scopeA; return r }

func TestPostgresRetentionProcessCAS(t *testing.T) {
	cfg := postgresFleetConfig(t)
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	rev := stage(t, s, "process-prune", "allow")
	r := Request{Scope: scopeA, Revisions: []string{rev}}
	p := execute(t, s, "retention_preview", r).(RetentionReport)
	r.ExpectedPlan = p.Plan
	raw, _ := json.Marshal(r)
	results := make(chan string, 2)
	var wg sync.WaitGroup
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestOperationsPruneWorker$")
			cmd.Env = append(os.Environ(), "NETCAP_OPERATIONS_WORKER=1", "NETCAP_FLEET_NAMESPACE="+cfg.DatabaseNamespace)
			cmd.Stdin = bytes.NewReader(raw)
			out, e := cmd.CombinedOutput()
			if e != nil {
				results <- "process failed: " + string(out)
				return
			}
			results <- string(out)
		}()
	}
	wg.Wait()
	close(results)
	committed, conflicts := 0, 0
	for result := range results {
		if strings.Contains(result, "PRUNE_COMMITTED") {
			committed++
		} else if strings.Contains(result, "PRUNE_CONFLICT") {
			conflicts++
		} else {
			t.Fatal(result)
		}
	}
	if committed != 1 || conflicts != 1 {
		t.Fatalf("process CAS winners=%d conflicts=%d", committed, conflicts)
	}
	if err = s.transactionMode(context.Background(), false, func(st *snapshot) error { return validate(st, false) }); err != nil {
		t.Fatal(err)
	}
}

func TestOperationsPruneWorker(t *testing.T) {
	if os.Getenv("NETCAP_OPERATIONS_WORKER") != "1" {
		t.Skip("subprocess helper")
	}
	cfg := fleetConfig(t)
	cfg.StateDir = ""
	cfg.DatabaseURL = os.Getenv("NETCAP_POSTGRES_TEST_URL")
	cfg.DatabaseNamespace = os.Getenv("NETCAP_FLEET_NAMESPACE")
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	var r Request
	if err = json.NewDecoder(os.Stdin).Decode(&r); err != nil {
		t.Fatal(err)
	}
	_, err = s.Execute(context.Background(), adminToken, "prune", r)
	if err == nil {
		fmt.Println("PRUNE_COMMITTED")
	} else if strings.Contains(err.Error(), "retention plan CAS conflict") {
		fmt.Println("PRUNE_CONFLICT")
	} else {
		t.Fatal(err)
	}
}

func TestRetentionReclaimsArtifactsProtectsRollbackAndFutureTargets(t *testing.T) {
	cfg := fleetConfig(t)
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	old := stage(t, s, "old", "allow")
	previous := stage(t, s, "previous", "deny")
	active := stage(t, s, "active", "allow")
	pending := stage(t, s, "pending", "deny")
	unused := stage(t, s, "unused", "allow")
	for i, rev := range []string{old, previous, active} {
		rollout(t, s, fmt.Sprintf("job-%d", i), rev, map[string]int64{"a": int64(i), "b": int64(i)}, nil)
		execute(t, s, "activate", Request{ID: fmt.Sprintf("job-%d", i), ExpectedPhase: "staged"})
	}
	rollout(t, s, "future", pending, map[string]int64{"a": 3, "b": 3}, []string{"a"})
	r := Request{Revisions: []string{old, previous, active, pending, unused}, Jobs: []string{"job-0", "job-1", "job-2", "future"}}
	plan := execute(t, s, "retention_preview", r).(RetentionReport)
	if !slices.Equal(plan.Revisions, sorted(old, unused)) || !slices.Equal(plan.Jobs, []string{"job-0", "job-1"}) {
		t.Fatalf("unsafe plan: %+v", plan)
	}
	r.ExpectedPlan = plan.Plan
	execute(t, s, "prune", r)
	var count int
	if err = s.disk.DB.QueryRow(`SELECT count(*) FROM artifacts`).Scan(&count); err != nil || count != 3 {
		t.Fatalf("artifacts count=%d err=%v", count, err)
	}
	if _, err = s.Execute(context.Background(), adminToken, "rollout", Request{Scope: scopeA, ID: "job-0", Revision: active, Targets: []string{"a"}, Expected: map[string]int64{"a": 3}, Deadline: time.Now().Add(time.Hour)}); err == nil {
		t.Fatal("archived job identity reused")
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = New(cfg)
	if err != nil {
		t.Fatal("restart references/artifacts inconsistent:", err)
	}
	defer s.Close()
	execute(t, s, "rollback", Request{ID: "job-2", ExpectedPhase: "active"})
	d, err := s.Desired(context.Background(), targetToken)
	if err != nil || d.Revision != previous {
		t.Fatalf("rollback invalidated: %+v %v", d, err)
	}
}

func sorted(values ...string) []string { slices.Sort(values); return values }

func TestRetentionCASAgainstConcurrentRollout(t *testing.T) {
	s, err := New(fleetConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	rev := stage(t, s, "race", "allow")
	r := Request{Scope: scopeA, Revisions: []string{rev}}
	plan := execute(t, s, "retention_preview", r).(RetentionReport)
	r.ExpectedPlan = plan.Plan
	var wg sync.WaitGroup
	wg.Add(2)
	errs := make(chan error, 2)
	go func() { defer wg.Done(); _, e := s.Execute(context.Background(), adminToken, "prune", r); errs <- e }()
	go func() {
		defer wg.Done()
		_, e := s.Execute(context.Background(), adminToken, "rollout", Request{Scope: scopeA, ID: "concurrent", Revision: rev, Targets: []string{"a"}, Expected: map[string]int64{"a": 0}, Deadline: time.Now().Add(time.Hour)})
		errs <- e
	}()
	wg.Wait()
	close(errs)
	successes := 0
	for e := range errs {
		if e == nil {
			successes++
		}
	}
	if successes != 1 {
		t.Fatalf("want one serialization winner, got %d", successes)
	}
	if err = s.transactionMode(context.Background(), false, func(st *snapshot) error { return validate(st, false) }); err != nil {
		t.Fatal(err)
	}
}

func TestAuditExportRolesRedactionPaginationAndRequiredCapacity(t *testing.T) {
	cfg := fleetConfig(t)
	cfg.AuditRequired = true
	cfg.Identities = append(cfg.Identities, Identity{ID: "auditor", Token: "auditor-secret-value", Scope: scopeA, Role: "auditor"}, Identity{ID: "viewer", Token: "viewer-secret-value", Scope: scopeA, Role: "viewer"})
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	stage(t, s, "secret-policy", "allow")
	call := func(token, path string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, path, nil)
		r.Header.Set("Authorization", "Bearer "+token)
		s.Handler().ServeHTTP(w, r)
		return w
	}
	path := "/api/v1/fleet/audit_export?limit=1"
	w := call("auditor-secret-value", path)
	if w.Code != 200 || w.Header().Get("Content-Type") != "application/x-ndjson" || w.Header().Get("X-Audit-More") != "true" || strings.Count(w.Body.String(), "\n") != 1 {
		t.Fatalf("export: %d %s %s", w.Code, w.Header(), w.Body.String())
	}
	for _, secret := range []string{adminToken, targetToken, "auditor-secret-value", "bundle", "headers", "secret-policy"} {
		if strings.Contains(w.Body.String(), secret) {
			t.Fatal("audit secret leak:", secret)
		}
	}
	if call("viewer-secret-value", path).Code != 403 || call(targetToken, path).Code != 401 {
		t.Fatal("export role boundary")
	}
	if _, err = s.Execute(context.Background(), "auditor-secret-value", "stage", Request{Bundle: `{"version":"1","id":"x","default":"allow"}`}); err == nil {
		t.Fatal("auditor mutation")
	}
	// Fill through the same durable transaction without thousands of fsyncs.
	err = s.transaction(context.Background(), func(st *snapshot) error {
		for len(st.Audit) < MaxAudit {
			s.audit(st, "administrator", "stage", scopeA, strings.Repeat("a", 64))
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	before := len(s.artifacts)
	if _, err = s.Execute(context.Background(), adminToken, "stage", Request{Scope: scopeA, Bundle: `{"version":"1","id":"full","mode":"enforce","default":"deny"}`}); err == nil {
		t.Fatal("required full audit accepted mutation")
	}
	if len(s.artifacts) != before {
		t.Fatal("audit failure changed artifacts")
	}
	plan := execute(t, s, "retention_preview", Request{}).(RetentionReport)
	execute(t, s, "audit_ack", Request{After: 100, ExpectedPlan: plan.Plan})
	stage(t, s, "after-export-ack", "deny")
	// SQLite read-only failure exercises the real durable sink error path.
	if _, err = s.disk.DB.Exec(`PRAGMA query_only=ON`); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Execute(context.Background(), adminToken, "stage", Request{Scope: scopeA, Bundle: `{"version":"1","id":"disk-failure","mode":"enforce","default":"deny"}`}); err == nil {
		t.Fatal("audit/database write failure accepted")
	}
}

func TestPostgresRetentionTwoOwners(t *testing.T) {
	cfg := postgresFleetConfig(t)
	a, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	b, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	rev := stage(t, a, "prune-cross-owner", "allow")
	r := Request{Revisions: []string{rev}}
	p := execute(t, b, "retention_preview", r).(RetentionReport)
	r.ExpectedPlan = p.Plan
	rollout(t, a, "pending-cross-owner", rev, map[string]int64{"a": 0, "b": 0}, []string{"a"})
	r.Scope = scopeA
	if _, err = b.Execute(context.Background(), adminToken, "prune", r); err == nil {
		t.Fatal("stale cross-owner plan accepted")
	}
	p = execute(t, b, "retention_preview", r).(RetentionReport)
	if len(p.Revisions) != 0 {
		t.Fatal("pending rollout lost artifact")
	}
	unused := stage(t, a, "unused-cross-owner", "deny")
	r = Request{Revisions: []string{unused}}
	p = execute(t, b, "retention_preview", r).(RetentionReport)
	r.ExpectedPlan = p.Plan
	execute(t, b, "prune", r)
	// Owner A must refresh its cache inside the authoritative transaction.
	if err = a.transactionMode(context.Background(), false, func(st *snapshot) error { return validate(st, false) }); err != nil {
		t.Fatal(err)
	}
}
