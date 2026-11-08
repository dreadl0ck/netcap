package firewall

import (
	"bufio"
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/internal/enforcer"
	"github.com/dreadl0ck/netcap/internal/firewallfleet"
	"github.com/dreadl0ck/netcap/internal/networkfirewall"
	"github.com/dreadl0ck/netcap/internal/policy"
)

// Re-exec the shared shipping command so service lifetime and signals cross a
// process boundary without writing or modifying the standalone entry point.
func TestFollowupCommandProcess(t *testing.T) {
	if os.Getenv("NETCAP_CLI_FOLLOWUP_PROCESS") != "1" {
		return
	}
	for i, arg := range os.Args {
		if arg == "--" {
			cmd := GetCommand()
			cmd.Name = "netcap-firewall"
			err := cmd.Run(context.Background(), append([]string{cmd.Name}, os.Args[i+1:]...))
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			os.Exit(0)
		}
	}
	os.Exit(2)
}

type followLog struct {
	sync.Mutex
	b []byte
}

func (l *followLog) Write(p []byte) (int, error) {
	l.Lock()
	defer l.Unlock()
	l.b = append(l.b, p...)
	if len(l.b) > 64<<10 {
		l.b = l.b[len(l.b)-(64<<10):]
	}
	return len(p), nil
}
func (l *followLog) String() string { l.Lock(); defer l.Unlock(); return string(l.b) }

type followProcess struct {
	cmd  *exec.Cmd
	done chan struct{}
	err  error
	log  followLog
}

func followStart(t *testing.T, args ...string) *followProcess {
	t.Helper()
	p := &followProcess{done: make(chan struct{})}
	p.cmd = exec.Command(os.Args[0], append([]string{"-test.run=^TestFollowupCommandProcess$", "--"}, args...)...)
	p.cmd.Env = append(os.Environ(), "NETCAP_CLI_FOLLOWUP_PROCESS=1")
	p.cmd.Stdout, p.cmd.Stderr = &p.log, &p.log
	if err := p.cmd.Start(); err != nil {
		t.Fatal(err)
	}
	go func() { p.err = p.cmd.Wait(); close(p.done) }()
	t.Cleanup(func() {
		select {
		case <-p.done:
			return
		default:
		}
		p.cmd.Process.Signal(syscall.SIGTERM)
		select {
		case <-p.done:
		case <-time.After(8 * time.Second):
			p.cmd.Process.Kill()
			<-p.done
			t.Error("command failed to stop")
		}
	})
	return p
}
func (p *followProcess) stop(t *testing.T) {
	t.Helper()
	p.cmd.Process.Signal(syscall.SIGTERM)
	select {
	case <-p.done:
		if p.err != nil {
			t.Fatalf("command stop: %v %s", p.err, p.log.String())
		}
	case <-time.After(8 * time.Second):
		t.Fatal("command shutdown timed out")
	}
}
func followJSON(t *testing.T, path string, v any) string {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}
func followAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().String()
}
func followWait(t *testing.T, p *followProcess, check func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if check() {
			return
		}
		select {
		case <-p.done:
			t.Fatalf("command exited: %v %s", p.err, p.log.String())
		default:
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("condition timed out: %s", p.log.String())
}
func followListen(t *testing.T, p *followProcess, addr string) {
	t.Helper()
	followWait(t, p, func() bool {
		c, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err != nil {
			return false
		}
		c.Close()
		return true
	})
}
func followRequest(t *testing.T, client *http.Client, method, url, token string, input any) (int, []byte) {
	t.Helper()
	var raw []byte
	if input != nil {
		var err error
		raw, err = json.Marshal(input)
		if err != nil {
			t.Fatal(err)
		}
	}
	r, err := http.NewRequest(method, url, bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("Authorization", "Bearer "+token)
	r.Header.Set("Content-Type", "application/json")
	res, err := client.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	body, err := io.ReadAll(io.LimitReader(res.Body, 2<<20))
	if err != nil {
		t.Fatal(err)
	}
	return res.StatusCode, body
}
func followClient(t *testing.T) *http.Client {
	t.Helper()
	c := &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{Proxy: nil}}
	t.Cleanup(c.CloseIdleConnections)
	return c
}
func followStatus(c *http.Client, url string) int {
	res, err := c.Get(url)
	if err != nil {
		return 0
	}
	defer res.Body.Close()
	io.Copy(io.Discard, res.Body)
	return res.StatusCode
}
func followPolicy(id, expression, scope string) policy.Bundle {
	rule := policy.Rule{ID: "deny", Action: "deny", Expression: expression}
	if scope != "" {
		rule.Effects = []policy.Effect{{Kind: "block_source", Target: "client", Duration: "10s", Scope: scope}}
	}
	return policy.Bundle{Version: "1", ID: id, Mode: "enforce", Default: "allow", Rules: []policy.Rule{rule}}
}
func followRuntime(t *testing.T, dir, origin string) (path, data, admin string) {
	t.Helper()
	data, admin = followAddr(t), followAddr(t)
	followJSON(t, filepath.Join(dir, "policy.json"), followPolicy("bootstrap", "false", ""))
	path = followJSON(t, filepath.Join(dir, "runtime.json"), map[string]any{"version": "netcap-firewall/v1", "listen": data, "adminListen": admin, "upstream": origin, "policyFile": "policy.json", "maxBodyBytes": 4096, "maxResponseBytes": 4096, "maxConcurrent": 4, "bodyTimeout": "1s", "trustedProxyCIDRs": []string{"127.0.0.0/8"}})
	return
}

func TestFleetEffectsAdmissionAndScopeGrantsCommand(t *testing.T) {
	const operator = "followup-operator-token-32-bytes-long"
	const target = "followup-target-token-32-bytes-long"
	const leaseToken = "followup-enforcer-token-32-bytes-long"
	t.Setenv("FOLLOW_OPERATOR", operator)
	t.Setenv("FOLLOW_TARGET", target)
	t.Setenv("FOLLOW_ENFORCER", leaseToken)
	t.Setenv("NETCAP_FIREWALL_ADMIN_TOKEN", "")
	dir := t.TempDir()
	scope := firewallfleet.Scope{Tenant: "tenant", App: "web"}
	network := enforcer.Scope{Hook: "forward", Interface: "eth0", DestinationCIDR: "10.1.0.0/24", Protocol: "tcp", Port: 443}
	e, err := enforcer.New(enforcer.Config{Token: leaseToken, Table: "netcap_firewall_followup", Scope: network, DryRun: true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	leaseAPI := httptest.NewTLSServer(e.Handler())
	defer leaseAPI.Close()
	ca := filepath.Join(dir, "ca.pem")
	if err = os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaseAPI.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	effects := followJSON(t, filepath.Join(dir, "effects.json"), map[string]any{"ca": ca, "scopes": map[string]any{"edge": map[string]any{"endpoint": leaseAPI.URL, "tokenEnv": "FOLLOW_ENFORCER", "network": network}}})
	controllerConfig := followJSON(t, filepath.Join(dir, "controller.json"), serviceFile{StateDir: filepath.Join(dir, "fleet"), AllowEffects: true, Identities: []principalFile{{ID: "operator", TokenEnv: "FOLLOW_OPERATOR", Scope: scope}}, Targets: []principalFile{{ID: "target", TokenEnv: "FOLLOW_TARGET", Scope: scope}}})
	addr := followAddr(t)
	controller := followStart(t, "fleet-controller", "--config", controllerConfig, "--listen", addr)
	followListen(t, controller, addr)
	c := followClient(t)
	base := "http://" + addr
	call := func(op string, input map[string]any) []byte {
		t.Helper()
		input["scope"] = scope
		method := "POST"
		if op == "status" || op == "audit" || op == "capabilities" {
			method = "GET"
			input = nil
		}
		code, raw := followRequest(t, c, method, base+"/api/v1/fleet/"+op, operator, input)
		if code != 200 {
			t.Fatalf("%s: %d %s", op, code, raw)
		}
		return raw
	}
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	defer origin.Close()
	config, data, admin := followRuntime(t, t.TempDir(), origin.URL)
	agent := followJSON(t, filepath.Join(dir, "agent.json"), map[string]any{"url": base, "tokenEnv": "FOLLOW_TARGET", "targetID": "target", "scope": scope, "stateDir": filepath.Join(dir, "agent"), "pollInterval": int64(20 * time.Millisecond), "allowEffects": true})
	p := followStart(t, "serve", "--config", config, "--fleet-agent-config", agent, "--effects-config", effects)
	followListen(t, p, admin)
	if got := followStatus(c, "http://"+admin+"/readyz"); got != 503 {
		t.Fatalf("cold fleet readiness %d", got)
	}
	activate := func(id, effectScope string, generation int) {
		t.Helper()
		b, _ := json.Marshal(followPolicy(id, "Path == '/effect'", effectScope))
		raw := call("stage", map[string]any{"bundle": string(b)})
		var staged map[string]string
		if err = json.Unmarshal(raw, &staged); err != nil {
			t.Fatal(err)
		}
		call("rollout", map[string]any{"id": id, "revision": staged["revision"], "targets": []string{"target"}, "expected": map[string]int{"target": generation}, "deadline": time.Now().Add(time.Minute)})
		call("activate", map[string]any{"id": id, "expected_phase": "staged"})
		followWait(t, p, func() bool {
			code, raw := followRequest(t, c, "GET", base+"/api/v1/fleet/desired", target, nil)
			return code == 200 && bytes.Contains(raw, []byte(staged["revision"])) && followStatus(c, "http://"+admin+"/readyz") == 200
		})
		followWait(t, p, func() bool {
			raw := call("status", map[string]any{})
			return bytes.Contains(raw, []byte(`"observed_revision":"`+staged["revision"]+`"`))
		})
	}
	code, _ := followRequest(t, c, "POST", base+"/api/v1/fleet/stage", operator, map[string]any{"scope": firewallfleet.Scope{Tenant: "foreign", App: "web"}, "bundle": `{}`})
	if code != 403 {
		t.Fatalf("foreign fleet scope accepted: %d", code)
	}
	request := func() {
		r, _ := http.NewRequest("GET", "http://"+data+"/effect", nil)
		r.Header.Set("X-Forwarded-For", "192.0.2.33")
		res, err := c.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		if res.StatusCode != 403 {
			t.Fatalf("effect decision %d", res.StatusCode)
		}
	}
	activate("ungranted", "foreign", 0)
	request()
	time.Sleep(100 * time.Millisecond)
	leases, err := e.List(t.Context())
	if err != nil || len(leases) != 0 {
		t.Fatalf("ungranted scope delivered leases: %+v %v", leases, err)
	}
	activate("granted", "edge", 1)
	request()
	followWait(t, p, func() bool {
		leases, err := e.List(t.Context())
		return err == nil && len(leases) == 1 && leases[0].Source == "192.0.2.33"
	})
	p.stop(t)
	controller.stop(t)
	if strings.Contains(p.log.String(), target) || strings.Contains(p.log.String(), leaseToken) || strings.Contains(p.log.String(), "192.0.2.33") {
		t.Fatal("source or token logged")
	}
}

func TestAgentAdmissionRequiresBroker(t *testing.T) {
	t.Setenv("FOLLOW_TARGET", strings.Repeat("a", 32))
	path := followJSON(t, filepath.Join(t.TempDir(), "agent.json"), map[string]any{"url": "http://127.0.0.1:1", "tokenEnv": "FOLLOW_TARGET", "targetID": "target", "scope": firewallfleet.Scope{Tenant: "tenant", App: "web"}, "stateDir": t.TempDir(), "allowEffects": true})
	if _, closeTransport, err := agentConfig(path, false); err == nil {
		closeTransport()
		t.Fatal("agent bootstrap granted effects without broker")
	}
	cfg, closeTransport, err := agentConfig(path, true)
	if err != nil {
		t.Fatal(err)
	}
	defer closeTransport()
	if !cfg.AllowEffects {
		t.Fatal("broker admission lost")
	}
}

func TestPacketUnreadyIsDenyNotFailure(t *testing.T) {
	p, err := policy.Compile(followPolicy("network", "false", ""))
	if err != nil {
		t.Fatal(err)
	}
	r := &runtimeEvaluator{ctx: t.Context()}
	r.SetPolicy(p)
	r.fleetUnready.Store(true)
	d, err := (packetEvaluator{r}).EvaluatePacket(networkfirewall.PacketEvent{SrcIP: "192.0.2.33"})
	if err != nil || d.Verdict != networkfirewall.Deny {
		t.Fatalf("unready could use fail-open: %+v %v", d, err)
	}
}

func TestGatewayFleetPublishesAndDrainsCommand(t *testing.T) {
	const token = "gateway-agent-secret-32-bytes-long"
	t.Setenv("FOLLOW_TARGET", token)
	dir := t.TempDir()
	scope := firewallfleet.Scope{Tenant: "tenant", App: "redis"}
	s, err := firewallfleet.New(firewallfleet.Config{StateDir: filepath.Join(dir, "controller"), Token: token, Targets: []firewallfleet.Enrollment{{ID: "redis", Token: strings.Repeat("t", 32), Scope: scope}}})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	t.Setenv("FOLLOW_TARGET", strings.Repeat("t", 32))
	controller := httptest.NewServer(s.Handler())
	defer controller.Close()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	var requests atomic.Int64
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				c.SetDeadline(time.Now().Add(5 * time.Second))
				wire := make([]byte, len("*1\r\n$4\r\nPING\r\n"))
				for {
					if _, err := io.ReadFull(c, wire); err != nil {
						return
					}
					requests.Add(1)
					fmt.Fprint(c, "+PONG\r\n")
				}
			}()
		}
	}()
	t.Cleanup(func() { l.Close(); <-done })
	policyPath := followJSON(t, filepath.Join(dir, "policy.json"), followPolicy("bootstrap", "false", ""))
	agent := followJSON(t, filepath.Join(dir, "agent.json"), map[string]any{"url": controller.URL, "tokenEnv": "FOLLOW_TARGET", "targetID": "redis", "scope": scope, "stateDir": filepath.Join(dir, "agent"), "pollInterval": int64(20 * time.Millisecond)})
	addr := followAddr(t)
	p := followStart(t, "gateway", "--protocol", "redis", "--policy", policyPath, "--listen", addr, "--upstream", l.Addr().String(), "--fleet-agent-config", agent)
	followListen(t, p, addr)
	ping := func() string {
		c, err := net.DialTimeout("tcp", addr, time.Second)
		if err != nil {
			return ""
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(time.Second))
		fmt.Fprint(c, "*1\r\n$4\r\nPING\r\n")
		line, _ := bufio.NewReader(c).ReadString('\n')
		return line
	}
	if line := ping(); !strings.Contains(line, "NOPERM") {
		t.Fatalf("cold gateway did not deny: %q", line)
	}
	execute := func(op string, r firewallfleet.Request) any {
		t.Helper()
		r.Scope = scope
		v, err := s.Execute(t.Context(), token, op, r)
		if err != nil {
			t.Fatalf("%s: %v", op, err)
		}
		return v
	}
	b, _ := json.Marshal(followPolicy("live", "false", ""))
	rev := execute("stage", firewallfleet.Request{Bundle: string(b)}).(map[string]string)["revision"]
	execute("rollout", firewallfleet.Request{ID: "live", Revision: rev, Targets: []string{"redis"}, Expected: map[string]int64{"redis": 0}, Deadline: time.Now().Add(time.Minute)})
	execute("activate", firewallfleet.Request{ID: "live", ExpectedPhase: "staged"})
	followWait(t, p, func() bool { return ping() == "+PONG\r\n" })
	execute("drain", firewallfleet.Request{Targets: []string{"redis"}, Expected: map[string]int64{"redis": 1}})
	followWait(t, p, func() bool { return strings.Contains(ping(), "NOPERM") })
	before := requests.Load()
	if line := ping(); !strings.Contains(line, "NOPERM") || requests.Load() != before {
		t.Fatalf("drained gateway reached origin: %q", line)
	}
	p.stop(t)
}

func TestControllerMaintainsIdleRolloutCommand(t *testing.T) {
	const token = "maintenance-operator-32-bytes-long"
	const target = "maintenance-target-32-bytes-long"
	t.Setenv("FOLLOW_OPERATOR", token)
	t.Setenv("FOLLOW_TARGET", target)
	dir := t.TempDir()
	state := filepath.Join(dir, "fleet")
	scope := firewallfleet.Scope{Tenant: "tenant", App: "idle"}
	config := firewallfleet.Config{StateDir: state, Token: token, Targets: []firewallfleet.Enrollment{{ID: "idle", Token: target, Scope: scope}}}
	s, err := firewallfleet.New(config)
	if err != nil {
		t.Fatal(err)
	}
	execute := func(op string, r firewallfleet.Request) any {
		t.Helper()
		r.Scope = scope
		v, err := s.Execute(t.Context(), token, op, r)
		if err != nil {
			t.Fatalf("%s: %v", op, err)
		}
		return v
	}
	b, _ := json.Marshal(followPolicy("initial", "false", ""))
	rev := execute("stage", firewallfleet.Request{Bundle: string(b)}).(map[string]string)["revision"]
	execute("rollout", firewallfleet.Request{ID: "initial", Revision: rev, Targets: []string{"idle"}, Expected: map[string]int64{"idle": 0}, Deadline: time.Now().Add(time.Minute)})
	execute("activate", firewallfleet.Request{ID: "initial", ExpectedPhase: "staged"})
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	file := followJSON(t, filepath.Join(dir, "controller.json"), serviceFile{StateDir: state, TokenEnv: "FOLLOW_OPERATOR", RollbackOnFailure: true, Targets: []principalFile{{ID: "idle", TokenEnv: "FOLLOW_TARGET", Scope: scope}}})
	addr := followAddr(t)
	p := followStart(t, "fleet-controller", "--config", file, "--listen", addr)
	followListen(t, p, addr)
	c := followClient(t)
	base := "http://" + addr + "/api/v1/fleet/"
	call := func(op string, input map[string]any) []byte {
		t.Helper()
		input["scope"] = scope
		code, raw := followRequest(t, c, "POST", base+op, token, input)
		if code != 200 {
			t.Fatalf("%s: %d %s", op, code, raw)
		}
		return raw
	}
	b, _ = json.Marshal(followPolicy("missed", "true", ""))
	raw := call("stage", map[string]any{"bundle": string(b)})
	var staged map[string]string
	if err = json.Unmarshal(raw, &staged); err != nil {
		t.Fatal(err)
	}
	call("rollout", map[string]any{"id": "missed", "revision": staged["revision"], "targets": []string{"idle"}, "expected": map[string]int{"idle": 1}, "deadline": time.Now().Add(300 * time.Millisecond)})
	call("activate", map[string]any{"id": "missed", "expected_phase": "staged"})
	// Observe durable state directly: status/desired requests also run maintenance
	// and would conceal a missing idle timer.
	db, err := sql.Open("sqlite", "file:"+filepath.Join(state, "fleet.sqlite")+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	followWait(t, p, func() bool {
		var raw []byte
		if err := db.QueryRowContext(t.Context(), "SELECT snapshot FROM fleet WHERE id=1").Scan(&raw); err != nil {
			return false
		}
		var snapshot struct {
			Jobs map[string]firewallfleet.Job `json:"jobs"`
		}
		if json.Unmarshal(raw, &snapshot) != nil {
			return false
		}
		return snapshot.Jobs["missed"].Phase == "rolledback"
	})
	p.stop(t)
}

func TestSharedGuardStartupProbeReadinessAndOutageCommand(t *testing.T) {
	const token = "shared-probe-token-32-bytes-long"
	t.Setenv("FOLLOW_STATE", token)
	t.Setenv("NETCAP_FIREWALL_ADMIN_TOKEN", "")
	dir := t.TempDir()
	addr := followAddr(t)
	stateConfig := followJSON(t, filepath.Join(dir, "state.json"), serviceFile{StateDir: filepath.Join(dir, "state"), Principals: []principalFile{{ID: "proxy", TokenEnv: "FOLLOW_STATE", Scope: firewallfleet.Scope{Tenant: "tenant", App: "probe"}}}})
	state := followStart(t, "sharedstate", "--config", stateConfig, "--listen", addr)
	followListen(t, state, addr)
	rate := followJSON(t, filepath.Join(dir, "rate.json"), map[string]any{"url": "http://" + addr, "tokenEnv": "FOLLOW_STATE", "id": "requests", "window": int64(time.Minute), "limit": 1, "unit": "request"})
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	defer origin.Close()
	runtime, data, admin := followRuntime(t, t.TempDir(), origin.URL)
	p := followStart(t, "serve", "--config", runtime, "--shared-rate-config", rate)
	followListen(t, p, admin)
	c := followClient(t)
	ready := "http://" + admin + "/readyz"
	// No data request is sent until readiness becomes true, as in Kubernetes.
	followWait(t, p, func() bool { return followStatus(c, ready) == 200 })
	if got := followStatus(c, "http://"+data+"/one"); got != 204 {
		t.Fatalf("startup health consumed quota: %d", got)
	}
	if got := followStatus(c, "http://"+data+"/two"); got != 429 {
		t.Fatalf("guard quota missing: %d", got)
	}
	state.stop(t)
	followWait(t, p, func() bool { return followStatus(c, ready) == 503 })
	if got := followStatus(c, "http://"+data+"/outage"); got < 400 {
		t.Fatalf("shared outage allowed traffic: %d", got)
	}
	state = followStart(t, "sharedstate", "--config", stateConfig, "--listen", addr)
	followListen(t, state, addr)
	followWait(t, p, func() bool { return followStatus(c, ready) == 200 })
	if got := followStatus(c, "http://"+data+"/three"); got != 429 {
		t.Fatalf("probe reset counter: %d", got)
	}
	p.stop(t)
	state.stop(t)
	if strings.Contains(p.log.String(), token) {
		t.Fatal("shared-state token logged")
	}
}
