package firewallfleet

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/internal/firewallstate"
)

func postgresFleetConfig(t *testing.T) Config {
	t.Helper()
	raw := os.Getenv("NETCAP_POSTGRES_TEST_URL")
	if raw == "" {
		t.Skip("NETCAP_POSTGRES_TEST_URL required for real PostgreSQL tests")
	}
	u, err := url.Parse(raw)
	if err != nil || !net.ParseIP(u.Hostname()).IsLoopback() {
		t.Fatal("PostgreSQL tests require a literal loopback host")
	}
	cfg := fleetConfig(t)
	cfg.StateDir = ""
	cfg.DatabaseURL = raw
	cfg.DatabaseNamespace = fmt.Sprintf("ncf_fleet_%d_%x", os.Getpid(), time.Now().UnixNano())
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		d, err := firewallstate.OpenPostgres(ctx, raw, cfg.DatabaseNamespace)
		if err != nil {
			t.Errorf("cleanup connection: %v", err)
			return
		}
		defer d.Close()
		if _, err = d.DB.ExecContext(ctx, `DROP SCHEMA "`+cfg.DatabaseNamespace+`" CASCADE`); err != nil {
			t.Errorf("cleanup schema: %v", err)
		}
	})
	return cfg
}

func TestPostgresFleetActiveActive(t *testing.T) {
	cfg := postgresFleetConfig(t)
	a, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	b, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = a.Close(); _ = b.Close() }()
	// Both processes must discover each other's immutable artifacts, not merely
	// serialize writes to a snapshot built from stale local artifact caches.
	revisions := make(chan string, 8)
	errs := make(chan error, 8)
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s := a
			if i%2 == 1 {
				s = b
			}
			v, err := s.Execute(context.Background(), adminToken, "stage", Request{Scope: scopeA, Bundle: fmt.Sprintf(`{"version":"1","id":"stage-%d","mode":"enforce","default":"allow"}`, i)})
			if err != nil {
				errs <- err
				return
			}
			revisions <- v.(map[string]string)["revision"]
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	close(revisions)
	var revision string
	for rev := range revisions {
		revision = rev
	}
	for _, id := range []string{"a", "b"} {
		execute(t, a, "rollout", Request{ID: "job-" + id, Revision: revision, Targets: []string{id}, Expected: map[string]int64{id: 0}, Deadline: time.Now().Add(time.Hour)})
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestPostgresFleetWorker$")
	cmd.Env = append(os.Environ(), "NETCAP_FLEET_WORKER=1", "NETCAP_FLEET_NAMESPACE="+cfg.DatabaseNamespace)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(stdout)
	line, err := reader.ReadString('\n')
	if err != nil || strings.TrimSpace(line) != "HA_READY" {
		_ = cmd.Wait()
		t.Fatalf("child readiness: %v %s", err, stderr.String())
	}
	lock, err := a.disk.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Rollback()
	if _, err = stdin.Write([]byte{1}); err != nil {
		t.Fatal(err)
	}
	_ = stdin.Close()
	line, err = reader.ReadString('\n')
	if err != nil || strings.TrimSpace(line) != "HA_ACTIVATING" {
		t.Fatalf("child activation barrier: %v %s", err, line)
	}
	child := make(chan struct {
		raw []byte
		err error
	}, 1)
	go func() {
		raw, err := io.ReadAll(reader)
		if err == nil {
			err = cmd.Wait()
		}
		child <- struct {
			raw []byte
			err error
		}{raw, err}
	}()
	select {
	case result := <-child:
		t.Fatalf("other process bypassed namespace transaction lock: %v %s", result.err, result.raw)
	case <-time.After(50 * time.Millisecond):
	}
	if err = lock.Rollback(); err != nil {
		t.Fatal(err)
	}
	execute(t, b, "activate", Request{ID: "job-a", ExpectedPhase: "staged"})
	result := <-child
	if result.err != nil || !strings.Contains(string(result.raw), "HA_RESULT activated") {
		t.Fatalf("child activation failed: %v %s", result.err, result.raw)
	}
	for _, s := range []*Service{a, b} {
		for _, token := range []string{targetToken, cfg.Targets[1].Token} {
			d, err := s.Desired(ctx, token)
			if err != nil || d.Generation != 1 || d.Revision != revision {
				t.Fatalf("lost independent target metadata %+v %v", d, err)
			}
		}
	}
	rev2 := stage(t, b, "second", "deny")
	execute(t, a, "rollout", Request{ID: "cas", Revision: rev2, Targets: []string{"a"}, Expected: map[string]int64{"a": 1}, Deadline: time.Now().Add(time.Hour)})
	var successes atomic.Int32
	for i := range 12 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s := a
			if i%2 == 1 {
				s = b
			}
			if _, err := s.Execute(ctx, adminToken, "activate", Request{Scope: scopeA, ID: "cas", ExpectedPhase: "staged"}); err == nil {
				successes.Add(1)
			}
		}()
	}
	wg.Wait()
	if successes.Load() != 1 {
		t.Fatalf("CAS winners %d", successes.Load())
	}
	if err = b.Acknowledge(ctx, targetToken, Ack{Revision: rev2, Generation: 2}); err != nil {
		t.Fatal(err)
	}
	status := execute(t, a, "status", Request{}).(Status)
	if status.Targets["a"].ObservedGeneration != 2 || status.Targets["b"].Generation != 1 {
		t.Fatalf("cross-node observations %+v", status.Targets)
	}
	changed := cfg
	changed.Targets = append([]Enrollment(nil), cfg.Targets...)
	changed.Targets[0].Scope = scopeB
	if drift, err := New(changed); err == nil {
		_ = drift.Close()
		t.Fatal("scope-drift controller accepted")
	}
	changed = cfg
	changed.AllowEffects = true
	if drift, err := New(changed); err == nil {
		_ = drift.Close()
		t.Fatal("admission-drift controller accepted")
	}
	_ = a.Close()
	_ = b.Close()
	a, err = New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	b, err = New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []*Service{a, b} {
		d, err := s.Desired(ctx, targetToken)
		if err != nil || d.Generation != 2 || d.Revision != rev2 {
			t.Fatalf("restart lost committed generation %+v %v", d, err)
		}
	}
}

func TestPostgresFleetWorker(t *testing.T) {
	if os.Getenv("NETCAP_FLEET_WORKER") != "1" {
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
	fmt.Println("HA_READY")
	if _, err = io.ReadFull(os.Stdin, make([]byte, 1)); err != nil {
		t.Fatal(err)
	}
	fmt.Println("HA_ACTIVATING")
	if _, err = s.Execute(context.Background(), adminToken, "activate", Request{Scope: scopeA, ID: "job-b", ExpectedPhase: "staged"}); err != nil {
		t.Fatal(err)
	}
	fmt.Println("HA_RESULT activated")
}

func mcpPostgresStage(t *testing.T, srv *httptest.Server, bundle string) string {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": map[string]any{"name": "fleet_stage", "arguments": map[string]any{"scope": scopeA, "bundle": bundle}}})
	req, err := http.NewRequest("POST", srv.URL+"/mcp", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+adminToken)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var result struct {
		Result struct {
			IsError bool `json:"isError"`
			Content []struct {
				Text string `json:"text"`
			} `json:"content"`
		} `json:"result"`
		Error json.RawMessage `json:"error"`
	}
	if err = json.NewDecoder(resp.Body).Decode(&result); err != nil || resp.StatusCode != 200 || result.Result.IsError || len(result.Result.Content) != 1 {
		t.Fatalf("MCP stage failed %d %+v %v", resp.StatusCode, result, err)
	}
	var revision struct {
		Revision string `json:"revision"`
	}
	if err = json.Unmarshal([]byte(result.Result.Content[0].Text), &revision); err != nil || revision.Revision == "" {
		t.Fatalf("MCP revision: %v", err)
	}
	return revision.Revision
}

func TestPostgresMCPAndAgentAcrossReplicas(t *testing.T) {
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
	one := httptest.NewServer(a.Handler())
	defer one.Close()
	rev := mcpPostgresStage(t, one, `{"version":"1","id":"mcp","mode":"enforce","default":"deny"}`)
	rollout(t, b, "mcp", rev, map[string]int64{"a": 0, "b": 0}, nil)
	execute(t, b, "activate", Request{ID: "mcp", ExpectedPhase: "staged"})
	var node atomic.Uint32
	handlers := []http.Handler{a.Handler(), b.Handler()}
	front := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { handlers[node.Add(1)%2].ServeHTTP(w, r) }))
	defer front.Close()
	target := &atomicTarget{}
	statuses, stop := startAgent(t, AgentConfig{URL: front.URL, Token: targetToken, TargetID: "a", Scope: scopeA, StateDir: filepath.Join(t.TempDir(), "agent"), PollInterval: 20 * time.Millisecond}, target)
	defer stop()
	awaitStatus(t, statuses, func(s AgentStatus) bool { return s.Ready && s.Generation == 1 })
	awaitObserved(t, b, "a", 1)
	req, _ := http.NewRequest("GET", one.URL+"/api/v1/fleet/status?tenant=tenant-a&app=app", nil)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	resp, err := one.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var status Status
	if err = json.NewDecoder(resp.Body).Decode(&status); err != nil || resp.StatusCode != 200 || status.Targets["a"].ObservedGeneration != 1 {
		t.Fatalf("HTTP status: %d %v", resp.StatusCode, err)
	}
	if target.Policy() == nil || target.Policy().Revision() != rev {
		t.Fatal("alternating controllers supplied inconsistent policy")
	}
}

// A destructive restart is allowed only for the explicitly labeled loopback
// test container; never apply this helper to an arbitrary operator database.
func restartTestContainer(t *testing.T) func() {
	t.Helper()
	name := os.Getenv("NETCAP_POSTGRES_TEST_CONTAINER")
	if !strings.HasPrefix(name, "ncf-ha-") {
		t.Skip("NETCAP_POSTGRES_TEST_CONTAINER=ncf-ha-* required for crash recovery test")
	}
	raw, err := exec.Command("docker", "inspect", name).Output()
	if err != nil {
		t.Fatal(err)
	}
	var inspect []struct {
		Config     struct{ Labels map[string]string }
		HostConfig struct {
			PortBindings map[string][]struct{ HostIp, HostPort string }
		}
		NetworkSettings struct {
			Ports map[string][]struct{ HostIp, HostPort string }
		}
	}
	if err = json.Unmarshal(raw, &inspect); err != nil || len(inspect) != 1 || inspect[0].Config.Labels["netcap.firewall.ha-test"] != "true" {
		t.Fatal("refusing to restart an unmarked container")
	}
	bindings := inspect[0].HostConfig.PortBindings["5432/tcp"]
	if len(bindings) != 1 || bindings[0].HostIp != "127.0.0.1" {
		t.Fatal("refusing nonloopback PostgreSQL test container")
	}
	parsed, _ := url.Parse(os.Getenv("NETCAP_POSTGRES_TEST_URL"))
	actual := inspect[0].NetworkSettings.Ports["5432/tcp"]
	if bindings[0].HostPort == "" {
		t.Fatal("crash recovery requires a fixed published loopback port; Docker reallocates ephemeral ports on restart")
	}
	if len(actual) != 1 || actual[0].HostIp != "127.0.0.1" || parsed == nil || parsed.Hostname() != "127.0.0.1" || parsed.Port() != actual[0].HostPort {
		t.Fatal("test URL does not address labeled container")
	}
	if out, err := exec.Command("docker", "kill", name).CombinedOutput(); err != nil {
		t.Fatalf("kill test database: %v %s", err, out)
	}
	return func() {
		t.Helper()
		if out, err := exec.Command("docker", "start", name).CombinedOutput(); err != nil {
			t.Fatalf("restart test database: %v %s", err, out)
		}
	}
}

func TestPostgresDatabaseCrashRecovery(t *testing.T) {
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
	var version int
	if err = a.disk.DB.QueryRow(`SHOW server_version_num`).Scan(&version); err != nil || version < 170000 || version >= 180000 {
		t.Fatalf("requires actual PostgreSQL 17: %d %v", version, err)
	}
	rev := stage(t, a, "survive-crash", "allow")
	rollout(t, b, "initial", rev, map[string]int64{"a": 0, "b": 0}, nil)
	execute(t, a, "activate", Request{ID: "initial", ExpectedPhase: "staged"})
	execute(t, b, "drain", Request{Targets: []string{"b"}, Expected: map[string]int64{"b": 1}})
	stateCfg := firewallstate.Config{DatabaseURL: cfg.DatabaseURL, DatabaseNamespace: cfg.DatabaseNamespace + "_s", Principals: []firewallstate.Principal{{ID: "counter", Token: targetToken, Scope: scopeA}}}
	stateA, err := firewallstate.New(stateCfg)
	if err != nil {
		t.Fatal(err)
	}
	defer stateA.Close()
	stateB, err := firewallstate.New(stateCfg)
	if err != nil {
		t.Fatal(err)
	}
	defer stateB.Close()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		d, err := firewallstate.OpenPostgres(ctx, cfg.DatabaseURL, stateCfg.DatabaseNamespace)
		if err != nil {
			t.Errorf("counter cleanup: %v", err)
			return
		}
		defer d.Close()
		_, err = d.DB.ExecContext(ctx, `DROP SCHEMA "`+stateCfg.DatabaseNamespace+`" CASCADE`)
		if err != nil {
			t.Error(err)
		}
	})
	key := firewallstate.Key{Revision: rev, Group: firewallstate.Digest("crash")}
	window := firewallstate.Window{Mode: "fixed", Duration: time.Hour}
	for i := range 20 {
		s := stateA
		if i%2 == 1 {
			s = stateB
		}
		v, err := s.Bind(scopeA).Count(context.Background(), key, window, time.Time{})
		if err != nil || v.Count != int64(i+1) {
			t.Fatalf("pre-crash count %+v %v", v, err)
		}
	}
	stateHTTP := httptest.NewServer(stateA.Handler())
	defer stateHTTP.Close()
	guard, err := firewallstate.NewGuard(firewallstate.GuardConfig{URL: stateHTTP.URL, Token: targetToken, ID: "health", Window: time.Hour, Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	if err = guard.Probe(context.Background()); err != nil {
		t.Fatal(err)
	}
	var replica atomic.Uint32
	handlers := []http.Handler{a.Handler(), b.Handler()}
	front := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { handlers[replica.Add(1)%2].ServeHTTP(w, r) }))
	defer front.Close()
	target := &atomicTarget{}
	statuses, stop := startAgent(t, AgentConfig{URL: front.URL, Token: targetToken, TargetID: "a", Scope: scopeA, StateDir: filepath.Join(t.TempDir(), "agent"), PollInterval: 20 * time.Millisecond, RequestTimeout: 100 * time.Millisecond, MaxStale: 60 * time.Millisecond}, target)
	defer stop()
	awaitStatus(t, statuses, func(s AgentStatus) bool { return s.Ready && s.Generation == 1 })
	awaitObserved(t, b, "a", 1)
	restart := restartTestContainer(t)
	restarted := false
	defer func() {
		if !restarted {
			restart()
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err = a.Execute(ctx, adminToken, "status", Request{Scope: scopeA}); err == nil {
		t.Fatal("controller served cached success during database outage")
	}
	if _, err = stateB.Bind(scopeA).Count(ctx, key, window, time.Time{}); err == nil {
		t.Fatal("counter succeeded without authoritative database")
	}
	if err = guard.Probe(ctx); err == nil {
		t.Fatal("health fabricated readiness during partition")
	}
	if ready, _ := guard.Ready(); ready {
		t.Fatal("guard ready during database failure")
	}
	awaitStatus(t, statuses, func(s AgentStatus) bool { return !s.Ready && s.Generation == 1 })
	restart()
	restarted = true
	deadline := time.Now().Add(15 * time.Second)
	for {
		probe, cancel := context.WithTimeout(context.Background(), time.Second)
		err = guard.Probe(probe)
		cancel()
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("database did not recover: %v", err)
		}
		time.Sleep(100 * time.Millisecond)
	}
	for _, s := range []*Service{a, b} {
		d, err := s.Desired(context.Background(), targetToken)
		if err != nil || d.Generation != 1 || d.Revision != rev {
			t.Fatalf("generation lost after WAL recovery %+v %v", d, err)
		}
		d, err = s.Desired(context.Background(), cfg.Targets[1].Token)
		if err != nil || d.Generation != 2 || !d.Draining {
			t.Fatalf("control generation lost after recovery %+v %v", d, err)
		}
	}
	awaitStatus(t, statuses, func(s AgentStatus) bool { return s.Ready && s.Generation == 1 })
	v, err := stateA.Bind(scopeA).Count(context.Background(), key, window, time.Time{})
	if err != nil || v.Count != 21 {
		t.Fatalf("committed counters lost after recovery %+v %v", v, err)
	}
	rev2 := mcpPostgresStage(t, front, `{"version":"1","id":"after-crash","mode":"enforce","default":"deny"}`)
	execute(t, a, "rollout", Request{ID: "recovery", Revision: rev2, Targets: []string{"a"}, Expected: map[string]int64{"a": 1}, Deadline: time.Now().Add(time.Hour)})
	execute(t, b, "activate", Request{ID: "recovery", ExpectedPhase: "staged"})
	awaitStatus(t, statuses, func(s AgentStatus) bool { return s.Ready && s.Generation == 2 })
	awaitObserved(t, a, "a", 2)
	fresh, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer fresh.Close()
	d, err := fresh.Desired(context.Background(), targetToken)
	if err != nil || d.Generation != 2 || d.Revision != rev2 || target.Policy().Revision() != rev2 {
		t.Fatalf("new controller after crash %+v %v", d, err)
	}
}
