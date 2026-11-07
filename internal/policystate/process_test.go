package policystate

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/internal/firewallstate"
	"github.com/dreadl0ck/netcap/internal/policy"
)

func TestNativeStateProcess(t *testing.T) {
	raw := os.Getenv("NCF_NATIVE_STATE_CHILD")
	if raw == "" {
		return
	}
	var cfg Config
	if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
		t.Fatal(err)
	}
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	fmt.Fprintln(os.Stdout, "http://"+l.Addr().String())
	if err := http.Serve(l, s.Handler()); err != nil {
		t.Fatal(err)
	}
}

type child struct {
	cmd  *exec.Cmd
	url  string
	done chan struct{}
}

func startProcess(t *testing.T, cfg Config) *child {
	t.Helper()
	raw, _ := json.Marshal(cfg)
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	p := &child{done: make(chan struct{})}
	p.cmd = exec.Command(executable, "-test.run=^TestNativeStateProcess$")
	p.cmd.Env = append(os.Environ(), "NCF_NATIVE_STATE_CHILD="+string(raw))
	out, err := p.cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	p.cmd.Stderr = &stderr
	if err := p.cmd.Start(); err != nil {
		t.Fatal(err)
	}
	go func() { _ = p.cmd.Wait(); close(p.done) }()
	t.Cleanup(func() { p.kill(t) })
	line := make(chan string, 1)
	go func() {
		scan := bufio.NewScanner(out)
		for scan.Scan() {
			if strings.HasPrefix(scan.Text(), "http://") {
				line <- scan.Text()
				return
			}
		}
		line <- ""
	}()
	select {
	case p.url = <-line:
		if p.url == "" {
			<-p.done
			t.Fatal("native child failed:", stderr.String())
		}
	case <-time.After(15 * time.Second):
		p.kill(t)
		t.Fatal("native child did not start")
	}
	c := client(t, p.url, cfg.Principals[0].Token)
	if err := c.Probe(context.Background()); err != nil {
		t.Fatal(err)
	}
	return p
}

func (p *child) kill(t *testing.T) {
	t.Helper()
	select {
	case <-p.done:
		return
	default:
	}
	_ = p.cmd.Process.Kill()
	select {
	case <-p.done:
	case <-time.After(10 * time.Second):
		t.Error("native child did not die")
	}
}

func TestSQLiteCrashWALRecovery(t *testing.T) {
	cfg := config(t)
	a := startProcess(t, cfg)
	c := client(t, a.url, testToken)
	p := descriptor(t, "crash", "sliding", "", 2)
	if d, err := c.Evaluate(context.Background(), p, policy.Event{}); err != nil || d.Verdict != "allow" {
		t.Fatal(d, err)
	}
	a.kill(t)
	b := startProcess(t, cfg)
	c = client(t, b.url, testToken)
	if d, err := c.Evaluate(context.Background(), p, policy.Event{}); err != nil || d.Verdict != "deny" {
		t.Fatal("SIGKILL lost an acknowledged WAL transition", d, err)
	}
}

func postgres(t *testing.T) (Config, func(*testing.T, bool)) {
	t.Helper()
	raw := os.Getenv("NETCAP_POSTGRES_TEST_URL")
	container := os.Getenv("NETCAP_POSTGRES_TEST_CONTAINER")
	command := func(active *testing.T, args ...string) string {
		active.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		out, err := exec.CommandContext(ctx, "docker", args...).CombinedOutput()
		if err != nil {
			active.Fatalf("docker %s: %s", args[0], out)
		}
		return strings.TrimSpace(string(out))
	}
	if raw == "" {
		if os.Getenv("NETCAP_POLICY_STATE_DOCKER") != "1" {
			t.Skip("NETCAP_POSTGRES_TEST_URL or NETCAP_POLICY_STATE_DOCKER=1 required")
		}
		container = command(t, "run", "--rm", "-d", "--label", "netcap.firewall.ha-test=true", "-e", "POSTGRES_PASSWORD=ncf-native-test", "-e", "POSTGRES_DB=native", "-p", "127.0.0.1::5432", "postgres:17.7-alpine")
		t.Cleanup(func() { command(t, "rm", "-f", container) })
		address := command(t, "port", container, "5432/tcp")
		raw = "postgres://postgres:ncf-native-test@" + address + "/native?sslmode=disable"
		deadline := time.Now().Add(15 * time.Second)
		ready := false
		for time.Now().Before(deadline) {
			if exec.Command("docker", "exec", container, "pg_isready", "-h", "127.0.0.1", "-U", "postgres", "-d", "native").Run() == nil {
				ready = true
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
		if !ready {
			t.Fatal("test PostgreSQL not ready")
		}
	}
	u, err := url.Parse(raw)
	if err != nil || !net.ParseIP(u.Hostname()).IsLoopback() {
		t.Fatal("PostgreSQL tests require literal loopback URL")
	}
	cfg := config(t)
	cfg.StateDir = ""
	cfg.DatabaseURL = raw
	cfg.DatabaseNamespace = fmt.Sprintf("ncf_native_%x", time.Now().UnixNano())
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		d, err := firewallstate.OpenPostgres(ctx, raw, cfg.DatabaseNamespace)
		if err != nil {
			t.Error(err)
			return
		}
		defer d.Close()
		_, err = d.DB.ExecContext(ctx, `DROP SCHEMA "`+cfg.DatabaseNamespace+`" CASCADE`)
		if err != nil {
			t.Error(err)
		}
	})
	pause := func(active *testing.T, on bool) {
		active.Helper()
		if container == "" {
			if os.Getenv("CI") != "" {
				active.Fatal("required partition fixture missing NETCAP_POSTGRES_TEST_CONTAINER")
			}
			active.Skip("partition injection requires an isolated PostgreSQL test container")
		}
		if command(active, "inspect", "--format", `{{index .Config.Labels "netcap.firewall.ha-test"}}`, container) != "true" {
			active.Fatal("partition injection requires the netcap.firewall.ha-test=true container label")
		}
		verb := "unpause"
		if on {
			verb = "pause"
		}
		command(active, verb, container)
	}
	return cfg, pause
}

func TestPostgresNativeStateAcrossProcesses(t *testing.T) {
	cfg, pause := postgres(t)
	a, b := startProcess(t, cfg), startProcess(t, cfg)
	ca, cb := client(t, a.url, testToken), client(t, b.url, testToken)
	p := descriptor(t, "global-fixed", "fixed", "", 100)
	var wg sync.WaitGroup
	var denied atomic.Int32
	for _, c := range []*Client{ca, cb} {
		wg.Add(1)
		go func(c *Client) {
			defer wg.Done()
			for i := 0; i < 50; i++ {
				d, err := c.Evaluate(context.Background(), p, policy.Event{ClientIP: "192.0.2.5"})
				if err != nil {
					t.Error(err)
					return
				}
				if d.Verdict == "deny" {
					denied.Add(1)
				}
			}
		}(c)
	}
	wg.Wait()
	if denied.Load() != 1 {
		t.Fatal("PostgreSQL replicas lost/doubled fixed counts", denied.Load())
	}
	distinct := descriptor(t, "global-distinct", "sliding", "Network.DstPort", 2)
	e := policy.Event{ClientIP: "192.0.2.5", Network: policy.NetworkEvent{DstPort: 443}}
	if d, err := ca.Evaluate(context.Background(), distinct, e); err != nil || d.Verdict != "allow" {
		t.Fatal(d, err)
	}
	e.Network.DstPort = 8443
	if d, err := cb.Evaluate(context.Background(), distinct, e); err != nil || d.Verdict != "deny" {
		t.Fatal("distinct windows were process-local", d, err)
	}
	otherScope := client(t, b.url, testToken+"-other")
	if d, err := otherScope.Evaluate(context.Background(), distinct, e); err != nil || d.Verdict != "allow" {
		t.Fatal("scopes shared native state", d, err)
	}
	seq, err := policy.Compile(policy.Bundle{Version: "1", ID: "global-sequence", Mode: "enforce", Default: "allow", Rules: []policy.Rule{{ID: "ordered", Action: "deny", Sequence: &policy.Sequence{Name: "dns-tls", Window: "1m", GroupBy: "ClientIP", Steps: []string{`Protocol == "dns"`, `Protocol == "tls"`}}}}})
	if err != nil {
		t.Fatal(err)
	}
	if d, err := ca.Evaluate(context.Background(), seq, policy.Event{Protocol: "dns"}); err != nil || d.Verdict != "allow" {
		t.Fatal(d, err)
	}
	if d, err := cb.Evaluate(context.Background(), seq, policy.Event{Protocol: "tls"}); err != nil || d.Verdict != "deny" {
		t.Fatal("sequence did not cross processes", d, err)
	}
	reload := descriptor(t, "reload", "fixed", "", 2)
	if d, err := ca.Evaluate(context.Background(), reload, policy.Event{ClientIP: "192.0.2.5"}); err != nil || d.Verdict != "allow" {
		t.Fatal("new revision reused old counts", d, err)
	}
	a.kill(t)
	a = startProcess(t, cfg)
	ca = client(t, a.url, testToken)
	if d, err := ca.Evaluate(context.Background(), reload, policy.Event{ClientIP: "192.0.2.5"}); err != nil || d.Verdict != "deny" {
		t.Fatal("restarted process forgot committed state", d, err)
	}
	changed := cfg
	changed.AllowEffects = true
	if wrong, err := New(changed); err == nil {
		_ = wrong.Close()
		t.Fatal("PostgreSQL bootstrap mismatch accepted")
	}
	t.Run("partition", func(t *testing.T) {
		pause(t, true)
		defer pause(t, false)
		fast, err := NewClient(ClientConfig{URL: b.url, Token: testToken, Timeout: 100 * time.Millisecond})
		if err != nil {
			t.Fatal(err)
		}
		defer fast.Close()
		if d, err := fast.Evaluate(context.Background(), reload, policy.Event{}); err == nil || d.Verdict != "" {
			t.Fatal("database partition returned a local decision", d, err)
		}
		if err := fast.Probe(context.Background()); err == nil || fast.Ready() {
			t.Fatal("partitioned authority remained ready")
		}
	})
}
