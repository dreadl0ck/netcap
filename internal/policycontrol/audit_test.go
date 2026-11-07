package policycontrol

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/internal/policy"
)

func TestOrderedReplayThresholdsAndBounds(t *testing.T) {
	s, dst := service(t, false)
	b := dst.Policy().Bundle()
	b.Rules[0].Threshold = &policy.Threshold{Count: 2, Window: "1h", GroupBy: "ClientIP"}
	c, err := policy.Compile(b)
	if err != nil {
		t.Fatal(err)
	}
	dst.current.Store(c)
	e := policy.Event{Method: "GET", Path: "/private", ClientIP: "192.0.2.1", Phase: "request"}
	for range 2 {
		var decisions []policy.Decision
		if err := json.Unmarshal(exec(t, s, "evaluate", Request{Events: []policy.Event{e, e, e}}), &decisions); err != nil {
			t.Fatal(err)
		}
		if len(decisions) != 3 || decisions[0].Verdict != "allow" || decisions[1].Verdict != "deny" || decisions[2].Verdict != "deny" {
			t.Fatalf("replay: %+v", decisions)
		}
	}
	if string(exec(t, s, "evaluate", Request{Events: []policy.Event{}})) != "[]" {
		t.Fatal("empty replay")
	}
	_, err = s.Execute(context.Background(), "evaluate", Request{Events: make([]policy.Event, MaxEvents+1)})
	wantStatus(t, err, 400)
	_, err = s.Execute(context.Background(), "evaluate", Request{Events: []policy.Event{e}, Event: e})
	wantStatus(t, err, 400)
	d, err := c.Evaluate(e)
	if err != nil || d.Verdict != "allow" || dst.writes.Load() != 0 {
		t.Fatalf("live contamination: %+v %v", d, err)
	}
	web := httptest.NewServer(s.Handler())
	defer web.Close()
	result := tool(t, web.Client(), web.URL, "explain_policy_decision", map[string]any{"events": []policy.Event{e, e}}, false)
	if !bytes.Contains(result, []byte(`"verdict":"deny"`)) || result[0] != '[' {
		t.Fatalf("MCP replay: %s", result)
	}
}

func TestStrictJSONAtTransportBoundary(t *testing.T) {
	s, dst := service(t, true)
	h := s.Handler()
	for _, body := range []string{
		`null`, `[]`, `{} {}`, `{"revision":"a","revision":"b"}`,
		`{"revision":"a","Revision":"b"}`, `{"Event":{}}`,
		`{"event":{"path":"a","path":"b"}}`, `{"events":[{"unknown":1}]}`,
		`{"events":[{"path":"a","Path":"b"}]}`, `{"events":[{"headers":{"x":["1"],"x":["2"]}}]}`,
	} {
		r := httptest.NewRequest("POST", "/api/v1/policy/evaluate", strings.NewReader(body))
		r.Header.Set("Authorization", "Bearer test-secret")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 400 {
			t.Fatalf("body %s: %d %s", body, w.Code, w.Body.String())
		}
	}
	for _, body := range []string{
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"stage_policy_revision","arguments":{"bundle":"a","bundle":"b"}}}`,
		`{"jsonrpc":"2.0","id":1,"method":"tools/list","method":"tools/call"}`,
	} {
		r := httptest.NewRequest("POST", "/mcp", strings.NewReader(body))
		r.Header.Set("Authorization", "Bearer test-secret")
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 400 {
			t.Fatalf("MCP duplicate: %d %s", w.Code, w.Body.String())
		}
		_, err := io.ReadAll(&lineLimitReader{reader: strings.NewReader(body + "\n")})
		if err == nil {
			t.Fatal("stdio accepted duplicate")
		}
	}
	if dst.writes.Load() != 0 {
		t.Fatal("invalid JSON changed target")
	}
}

func TestMCPOriginVersionAndCancellation(t *testing.T) {
	s, dst := service(t, true)
	for _, header := range []struct {
		name, value string
		status      int
	}{
		{"Origin", "https://evil.invalid", 403}, {"Origin", "null", 403},
		{"MCP-Protocol-Version", "1900-01-01", 400},
		{"MCP-Protocol-Version", "2025-03-26", 200},
	} {
		r := httptest.NewRequest("POST", "/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
		r.Header.Set("Authorization", "Bearer test-secret")
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set(header.name, header.value)
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		if w.Code != header.status {
			t.Fatalf("%s: %d %s", header.name, w.Code, w.Body.String())
		}
	}
	if err := s.acquire(context.Background()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		r := httptest.NewRequest("POST", "/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"stage_policy_revision","arguments":{"bundle":"invalid","idempotency_key":"cancelled"}}}`)).WithContext(ctx)
		r.Header.Set("Authorization", "Bearer test-secret")
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		done <- w
	}()
	select {
	case w := <-done:
		s.release()
		// The SDK may omit the response once its HTTP context is cancelled.
		if ctx.Err() == nil || (w.Body.Len() != 0 && !strings.Contains(w.Body.String(), "cancelled")) {
			t.Fatalf("cancellation: %s", w.Body.String())
		}
	case <-time.After(2 * time.Second):
		s.release()
		t.Fatal("MCP ignored cancellation while waiting for service lock")
	}
	if dst.writes.Load() != 0 {
		t.Fatal("cancelled call mutated target")
	}
	if other, err := New(s.cfg, target(t)); err == nil {
		_ = other.Close()
		t.Fatal("cancelled call released singleton")
	}
	stage(t, s, "after-cancel")
}

func TestTransactionFailureIsAtomic(t *testing.T) {
	for _, table := range []string{"audit", "receipts"} {
		t.Run(table, func(t *testing.T) {
			s, dst := service(t, true)
			initial := dst.Policy().Revision()
			rev := stage(t, s, "failure")
			if _, err := s.db.Exec(fmt.Sprintf(`CREATE TRIGGER fail_mutation BEFORE INSERT ON %s BEGIN SELECT RAISE(ABORT, 'injected persistence failure'); END`, table)); err != nil {
				t.Fatal(err)
			}
			r := Request{Revision: rev, ExpectedRevision: initial, IdempotencyKey: "retry-failed"}
			_, err := s.Execute(context.Background(), "activate", r)
			wantStatus(t, err, 500)
			var active string
			if err := s.db.QueryRow(`SELECT revision FROM deployment`).Scan(&active); err != nil {
				t.Fatal(err)
			}
			var receipts, audits int
			if err := s.db.QueryRow(`SELECT COUNT(*) FROM receipts`).Scan(&receipts); err != nil {
				t.Fatal(err)
			}
			if err := s.db.QueryRow(`SELECT COUNT(*) FROM audit`).Scan(&audits); err != nil {
				t.Fatal(err)
			}
			if active != initial || dst.Policy().Revision() != initial || dst.writes.Load() != 0 || receipts != 1 || audits != 1 {
				t.Fatalf("partial transaction: active=%s receipts=%d audits=%d writes=%d", active, receipts, audits, dst.writes.Load())
			}
			if _, err := s.db.Exec(`DROP TRIGGER fail_mutation`); err != nil {
				t.Fatal(err)
			}
			exec(t, s, "activate", r)
			if dst.Policy().Revision() != rev || dst.writes.Load() != 1 {
				t.Fatal("failed request poisoned retry")
			}
		})
	}
}

type observingTarget struct {
	*testTarget
	onSet func(*policy.Compiled)
}

func (t *observingTarget) SetPolicy(c *policy.Compiled) {
	if t.onSet != nil {
		t.onSet(c)
	}
	t.testTarget.SetPolicy(c)
}

func TestCommitPrecedesTargetAndReceiptNeverReattaches(t *testing.T) {
	dst := &observingTarget{testTarget: target(t)}
	s, err := New(Config{Token: "secret", Managed: true, StateDir: filepath.Join(t.TempDir(), "state")}, dst)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	initial := dst.Policy().Revision()
	rev := stage(t, s, "commit")
	r := Request{Revision: rev, ExpectedRevision: initial, IdempotencyKey: "committed"}
	dst.onSet = func(c *policy.Compiled) {
		var active string
		if err := s.db.QueryRow(`SELECT revision FROM deployment`).Scan(&active); err != nil {
			t.Fatal(err)
		}
		var count int
		if err := s.db.QueryRow(`SELECT COUNT(*) FROM receipts WHERE key='committed'`).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if active != c.Revision() || count != 1 {
			t.Fatal("target updated before durable deployment and receipt")
		}
	}
	exec(t, s, "activate", r)
	dst.onSet = nil
	exec(t, s, "rollback", Request{ExpectedRevision: rev, IdempotencyKey: "roll"})
	exec(t, s, "activate", r)
	if dst.Policy().Revision() != initial || dst.writes.Load() != 2 {
		t.Fatal("historical receipt reattached old deployment")
	}
}

// Minimal enforcement adapter: the WAF's full integration belongs to its owner.
func TestHTTPMCPActivationControlsOriginTraffic(t *testing.T) {
	var hits atomic.Int32
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1); _, _ = w.Write([]byte("origin")) }))
	defer origin.Close()
	dst := target(t)
	c, _, err := compile([]byte(`{"version":"1","id":"allow","mode":"enforce","default":"allow"}`))
	if err != nil {
		t.Fatal(err)
	}
	dst.current.Store(c)
	s, err := New(Config{Token: "test-secret", Managed: true, StateDir: filepath.Join(t.TempDir(), "state")}, dst)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	admin := httptest.NewServer(s.Handler())
	defer admin.Close()
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		d, err := dst.Policy().Evaluate(policy.Event{Method: r.Method, Path: r.URL.Path, Phase: "request"})
		if err != nil {
			http.Error(w, "evaluate", 500)
			return
		}
		if d.Verdict == "deny" {
			http.Error(w, "denied", 403)
			return
		}
		resp, err := origin.Client().Get(origin.URL + r.URL.Path)
		if err != nil {
			http.Error(w, "origin", 502)
			return
		}
		defer resp.Body.Close()
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)
	}))
	defer proxy.Close()
	probe := func(path string, status int, count int32) {
		t.Helper()
		resp, err := proxy.Client().Get(proxy.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != status || hits.Load() != count {
			t.Fatalf("probe %s: status=%d hits=%d", path, resp.StatusCode, hits.Load())
		}
	}
	probe("/private", 200, 1)
	var staged struct {
		Revision string `json:"revision"`
	}
	if err := json.Unmarshal(tool(t, admin.Client(), admin.URL, "stage_policy_revision", map[string]any{"bundle": bundle("origin"), "idempotency_key": "origin-stage"}, false), &staged); err != nil {
		t.Fatal(err)
	}
	probe("/private", 200, 2)
	tool(t, admin.Client(), admin.URL, "activate_policy_deployment", map[string]any{"revision": staged.Revision, "expected_revision": c.Revision(), "idempotency_key": "origin-activate"}, false)
	probe("/private", 403, 2)
	probe("/public", 200, 3)
	tool(t, admin.Client(), admin.URL, "rollback_policy_deployment", map[string]any{"expected_revision": staged.Revision, "idempotency_key": "origin-rollback"}, false)
	probe("/private", 200, 4)
}

func TestCounterResetAndHistoricalReceipts(t *testing.T) {
	s, dst := service(t, true)
	initial := dst.Policy().Revision()
	b := dst.Policy().Bundle()
	b.ID = "threshold"
	b.Rules[0].Threshold = &policy.Threshold{Count: 2, Window: "1h", GroupBy: "ClientIP"}
	raw, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	var staged struct {
		Revision string `json:"revision"`
	}
	if err := json.Unmarshal(exec(t, s, "stage", Request{Bundle: string(raw), IdempotencyKey: "threshold-stage"}), &staged); err != nil {
		t.Fatal(err)
	}
	r := Request{Revision: staged.Revision, ExpectedRevision: initial, IdempotencyKey: "threshold-activate"}
	exec(t, s, "activate", r)
	event := policy.Event{Method: "GET", Path: "/private", ClientIP: "192.0.2.1", Phase: "request"}
	probe := func(verdict string) {
		t.Helper()
		d, err := dst.Policy().Evaluate(event)
		if err != nil || d.Verdict != verdict {
			t.Fatalf("wanted %s: %+v %v", verdict, d, err)
		}
	}
	probe("allow")
	exec(t, s, "activate", r)
	exec(t, s, "activate", Request{Revision: staged.Revision, ExpectedRevision: staged.Revision, IdempotencyKey: "threshold-noop"})
	probe("deny")
	back := Request{ExpectedRevision: staged.Revision, IdempotencyKey: "threshold-back"}
	exec(t, s, "rollback", back)
	exec(t, s, "rollback", Request{ExpectedRevision: initial, IdempotencyKey: "threshold-return"})
	probe("allow")
	// Retrying an old rollback receipt cannot undo the newer return deployment.
	exec(t, s, "rollback", back)
	probe("deny")
	if dst.Policy().Revision() != staged.Revision || dst.writes.Load() != 3 {
		t.Fatal("receipt changed current attachment")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	fresh := target(t)
	restarted, err := New(s.cfg, fresh)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	d, err := fresh.Policy().Evaluate(event)
	if err != nil || d.Verdict != "allow" {
		t.Fatalf("restart retained runtime counters: %+v %v", d, err)
	}
	exec(t, restarted, "activate", r)
	d, err = fresh.Policy().Evaluate(event)
	if err != nil || d.Verdict != "deny" || fresh.writes.Load() != 1 {
		t.Fatalf("persisted receipt reset counters: %+v %v", d, err)
	}
}

func TestRecoveryAfterCommitBeforeAttachment(t *testing.T) {
	dst := &observingTarget{testTarget: target(t)}
	cfg := Config{Token: "secret", Managed: true, StateDir: filepath.Join(t.TempDir(), "state")}
	s, err := New(cfg, dst)
	if err != nil {
		t.Fatal(err)
	}
	initial := dst.Policy().Revision()
	rev := stage(t, s, "interrupted")
	r := Request{Revision: rev, ExpectedRevision: initial, IdempotencyKey: "interrupted"}
	dst.onSet = func(*policy.Compiled) { panic("interrupted after commit") }
	func() {
		defer func() {
			if recover() != "interrupted after commit" {
				t.Error("did not interrupt attachment")
			}
		}()
		_, _ = s.Execute(context.Background(), "activate", r)
	}()
	if dst.Policy().Revision() != initial {
		t.Fatal("test did not interrupt attachment")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	fresh := target(t)
	s, err = New(cfg, fresh)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if fresh.Policy().Revision() != rev {
		t.Fatal("restart did not restore committed desired state")
	}
	exec(t, s, "activate", r)
	if fresh.writes.Load() != 1 {
		t.Fatal("receipt retry reattached after recovery")
	}
}

func TestPrivateStateAndEscapedPaths(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state?mode=memory#fragment")
	cfg := Config{Token: "secret", Managed: true, StateDir: dir}
	s, err := New(cfg, target(t))
	if err != nil {
		t.Fatal(err)
	}
	stage(t, s, "escaped")
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"policycontrol.sqlite", "policycontrol.lock"} {
		info, err := os.Stat(filepath.Join(dir, name))
		if err != nil || info.Mode().Perm() != 0600 {
			t.Fatalf("state file %s: %v %v", name, info, err)
		}
	}
	s, err = New(cfg, target(t))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(exec(t, s, "audit", Request{}), []byte("stage")) {
		t.Fatal("URI characters lost persisted state")
	}
	_ = s.Close()
	if err := os.Chmod(dir, 0755); err != nil {
		t.Fatal(err)
	}
	if s, err = New(cfg, target(t)); err == nil {
		_ = s.Close()
		t.Fatal("public state directory accepted")
	}
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(dir, "policycontrol.sqlite"), 0644); err != nil {
		t.Fatal(err)
	}
	if s, err = New(cfg, target(t)); err == nil {
		_ = s.Close()
		t.Fatal("public state file accepted")
	}
}

func TestCommitFailureRollsBackAndRemainsUsable(t *testing.T) {
	s, dst := service(t, true)
	initial := dst.Policy().Revision()
	rev := stage(t, s, "commit-failure")
	// Deferred constraints fail at COMMIT, after all mutation statements succeed.
	if _, err := s.db.Exec(`PRAGMA foreign_keys=ON;
		CREATE TABLE parent(id INTEGER PRIMARY KEY);
		CREATE TABLE child(id INTEGER REFERENCES parent(id) DEFERRABLE INITIALLY DEFERRED);
		CREATE TRIGGER fail_commit AFTER INSERT ON receipts BEGIN INSERT INTO child VALUES(1); END;`); err != nil {
		t.Fatal(err)
	}
	r := Request{Revision: rev, ExpectedRevision: initial, IdempotencyKey: "commit-failure"}
	_, err := s.Execute(context.Background(), "activate", r)
	wantStatus(t, err, 500)
	if dst.Policy().Revision() != initial || dst.writes.Load() != 0 {
		t.Fatal("commit failure changed target")
	}
	if _, err := s.db.Exec(`DROP TRIGGER fail_commit`); err != nil {
		t.Fatal(err)
	}
	exec(t, s, "activate", r)
	if dst.Policy().Revision() != rev || dst.writes.Load() != 1 {
		t.Fatal("commit failure left transaction or receipt behind")
	}
}

func TestCancelledSQLTransactionKeepsOwnership(t *testing.T) {
	s, _ := service(t, true)
	ctx, cancel := context.WithCancel(context.Background())
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	_ = tx.Rollback()
	if other, err := New(s.cfg, target(t)); err == nil {
		_ = other.Close()
		t.Fatal("cancelled SQL transaction released StateDir ownership")
	}
	stage(t, s, "after-sql-cancel")
}
