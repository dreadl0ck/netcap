package main

import (
	"bytes"
	"context"
	"encoding/json"
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

	"golang.org/x/net/dns/dnsmessage"
)

const adminToken = "cli-integration-token-32-bytes-long"

var executable string

// Exercise the shipping entry point, including its signal handling. Matching
// build tags keeps the engine validation meaningful in both test variants.
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "netcap-firewall-cli-*")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	executable = filepath.Join(dir, "netcap-firewall")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	args := []string{"build", "-o", executable}
	tags := strings.Trim(strings.Join([]string{cliBuildTags, http3BuildTag}, ","), ",")
	if tags != "" {
		args = append(args, "-tags", tags)
	}
	args = append(args, ".")
	cmd := exec.CommandContext(ctx, "go", args...)
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
	err = cmd.Run()
	cancel()
	code := 1
	if err == nil {
		code = m.Run()
	} else {
		fmt.Fprintln(os.Stderr, "build shipping CLI:", err)
	}
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

type boundedLog struct {
	mu sync.Mutex
	b  []byte
}

func (b *boundedLog) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	n := len(p)
	const limit = 64 << 10
	if len(p) >= limit {
		b.b = append(b.b[:0], p[len(p)-limit:]...)
	} else {
		if len(b.b)+len(p) > limit {
			b.b = b.b[len(b.b)+len(p)-limit:]
		}
		b.b = append(b.b, p...)
	}
	return n, nil
}

func (b *boundedLog) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return string(b.b)
}

func cliEnv(token string) []string {
	env := []string{}
	for _, value := range os.Environ() {
		if !strings.HasPrefix(value, "NETCAP_FIREWALL_ADMIN_TOKEN=") {
			env = append(env, value)
		}
	}
	return append(env, "NETCAP_FIREWALL_ADMIN_TOKEN="+token)
}

func runCLI(t *testing.T, token string, args ...string) (string, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, executable, args...)
	cmd.Env = cliEnv(token)
	var log boundedLog
	cmd.Stdout, cmd.Stderr = &log, &log
	err := cmd.Run()
	if ctx.Err() != nil {
		t.Fatalf("CLI %v timed out: %s", args, log.String())
	}
	return log.String(), err
}

type process struct {
	cmd    *exec.Cmd
	done   chan struct{}
	err    error
	log    boundedLog
	cancel context.CancelFunc
}

func startCLI(t *testing.T, token string, args ...string) *process {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	p := &process{done: make(chan struct{}), cancel: cancel}
	p.cmd = exec.CommandContext(ctx, executable, args...)
	p.cmd.Env = cliEnv(token)
	p.cmd.Stdout, p.cmd.Stderr = &p.log, &p.log
	if err := p.cmd.Start(); err != nil {
		cancel()
		t.Fatal(err)
	}
	go func() { p.err = p.cmd.Wait(); close(p.done) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-p.done:
		case <-time.After(5 * time.Second):
			t.Error("subprocess did not exit after cancellation")
		}
	})
	return p
}

func (p *process) stop(t *testing.T) {
	t.Helper()
	if err := p.cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatalf("SIGTERM: %v; %s", err, p.log.String())
	}
	select {
	case <-p.done:
		if p.err != nil {
			t.Fatalf("unclean SIGTERM: %v; %s", p.err, p.log.String())
		}
	case <-time.After(5 * time.Second):
		p.cancel()
		t.Fatalf("SIGTERM did not drain: %s", p.log.String())
	}
}

func freeAddress(t *testing.T, network string) string {
	t.Helper()
	if network == "udp" {
		l, err := net.ListenPacket(network, "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer l.Close()
		return l.LocalAddr().String()
	}
	l, err := net.Listen(network, "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().String()
}

func writeFile(t *testing.T, path, contents string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(contents), 0600); err != nil {
		t.Fatal(err)
	}
}

func bundle(id, expression string) string {
	return fmt.Sprintf(`{"version":"netcap-policy/v1","id":%q,"mode":"enforce","default":"allow","rules":[{"id":"block","phase":"request","expression":%q,"action":"deny","status":403}]}`, id, expression)
}

func runtimeConfig(t *testing.T, upstream, admin string) (string, string) {
	t.Helper()
	dir := t.TempDir()
	data := freeAddress(t, "tcp")
	for data == admin {
		data = freeAddress(t, "tcp")
	}
	writeFile(t, filepath.Join(dir, "policy.json"), bundle("bootstrap", "Path == '/bootstrap-blocked'"))
	config := fmt.Sprintf(`{"version":"netcap-firewall/v1","listen":%q,"adminListen":%q,"upstream":%q,"policyFile":"policy.json","maxBodyBytes":1048576,"maxResponseBytes":1048576,"maxConcurrent":32,"bodyTimeout":"5s"}`, data, admin, upstream)
	path := filepath.Join(dir, "runtime.json")
	writeFile(t, path, config)
	return path, "http://" + data
}

func httpClient(t *testing.T) *http.Client {
	t.Helper()
	c := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{Proxy: nil}}
	t.Cleanup(c.CloseIdleConnections)
	return c
}

func waitReady(t *testing.T, p *process, client *http.Client, url string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	tick := time.NewTicker(20 * time.Millisecond)
	defer tick.Stop()
	for {
		r, err := client.Get(url)
		if err == nil {
			_, _ = io.Copy(io.Discard, r.Body)
			_ = r.Body.Close()
			if r.StatusCode == http.StatusOK {
				return
			}
		}
		select {
		case <-p.done:
			t.Fatalf("server exited before ready: %v; %s", p.err, p.log.String())
		case <-ctx.Done():
			t.Fatalf("readiness deadline: %v; %s", err, p.log.String())
		case <-tick.C:
		}
	}
}

type rpcReply struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      int             `json:"id"`
	Result  json.RawMessage `json:"result"`
	Error   json.RawMessage `json:"error"`
}

func rpc(client *http.Client, url, token, method string, params any) (json.RawMessage, error) {
	b, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest(http.MethodPost, url+"/mcp", bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("MCP-Protocol-Version", "2025-03-26")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if res.StatusCode != 200 {
		return nil, fmt.Errorf("MCP HTTP %d: %s", res.StatusCode, raw)
	}
	var reply rpcReply
	if err := json.Unmarshal(raw, &reply); err != nil {
		return nil, err
	}
	if reply.JSONRPC != "2.0" || reply.ID != 1 || len(reply.Error) != 0 || len(reply.Result) == 0 {
		return nil, fmt.Errorf("invalid RPC reply: %s", raw)
	}
	return reply.Result, nil
}

func tool(client *http.Client, url, name string, args any) (map[string]any, error) {
	raw, err := rpc(client, url, adminToken, "tools/call", map[string]any{"name": name, "arguments": args})
	if err != nil {
		return nil, err
	}
	var result struct {
		IsError bool                          `json:"isError"`
		Content []struct{ Type, Text string } `json:"content"`
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		return nil, err
	}
	if result.IsError || len(result.Content) != 1 || result.Content[0].Type != "text" {
		return nil, fmt.Errorf("tool %s: %s", name, raw)
	}
	var value map[string]any
	err = json.Unmarshal([]byte(result.Content[0].Text), &value)
	return value, err
}

func mustTool(t *testing.T, c *http.Client, url, name string, args any) map[string]any {
	t.Helper()
	v, err := tool(c, url, name, args)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func revision(t *testing.T, v map[string]any) string {
	t.Helper()
	r, ok := v["revision"].(string)
	if !ok || r == "" {
		t.Fatalf("missing revision: %v", v)
	}
	return r
}

func post(c *http.Client, url, body string) error {
	res, err := c.Post(url, "text/plain", strings.NewReader(body))
	if err != nil {
		return err
	}
	defer res.Body.Close()
	_, err = io.Copy(io.Discard, res.Body)
	if err != nil {
		return err
	}
	if res.StatusCode != 403 {
		return fmt.Errorf("blocked POST status = %d", res.StatusCode)
	}
	return nil
}

func TestShippingManagedLifecycle(t *testing.T) {
	var calls atomic.Int64
	var originBody atomic.Value
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		originBody.Store(string(b))
		calls.Add(1)
		w.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(w, "instrumented-origin")
	}))
	defer origin.Close()
	admin := freeAddress(t, "tcp")
	config, data := runtimeConfig(t, origin.URL, admin)
	adminURL := "http://" + admin
	state := filepath.Join(t.TempDir(), "state")
	args := []string{"serve", "--config", config, "--managed", "--state-dir", state}
	p := startCLI(t, adminToken, args...)
	c := httpClient(t)
	waitReady(t, p, c, adminURL+"/readyz")
	if out, err := runCLI(t, "", "healthcheck", "--url", adminURL+"/readyz"); err != nil {
		t.Fatalf("healthcheck: %v %s", err, out)
	}
	if _, err := rpc(c, adminURL, "", "tools/list", map[string]any{}); err == nil || !strings.Contains(err.Error(), "401") {
		t.Fatalf("unauthenticated MCP: %v", err)
	}
	init, err := rpc(c, adminURL, adminToken, "initialize", map[string]any{"protocolVersion": "2025-03-26", "capabilities": map[string]any{}, "clientInfo": map[string]string{"name": "cli-integration", "version": "1"}})
	if err != nil {
		t.Fatal(err)
	}
	var initialized struct {
		ProtocolVersion string                `json:"protocolVersion"`
		ServerInfo      struct{ Name string } `json:"serverInfo"`
	}
	if err := json.Unmarshal(init, &initialized); err != nil || initialized.ProtocolVersion != "2025-03-26" || initialized.ServerInfo.Name != "netcap-policycontrol" {
		t.Fatalf("initialize: %s (%v)", init, err)
	}
	listed, err := rpc(c, adminURL, adminToken, "tools/list", map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	var list struct {
		Tools []struct{ Name string } `json:"tools"`
	}
	if err := json.Unmarshal(listed, &list); err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for _, entry := range list.Tools {
		names[entry.Name] = true
	}
	for _, name := range []string{"get_policy_revision", "stage_policy_revision", "activate_policy_deployment", "rollback_policy_deployment"} {
		if !names[name] {
			t.Fatalf("tools/list missing %s: %s", name, listed)
		}
	}
	initial := revision(t, mustTool(t, c, adminURL, "get_policy_revision", map[string]any{}))
	body := strings.Repeat("safe-prefix-", 8192) + "late-cli-deny"
	// Negative control: exactly the same payload must reach the origin before activation.
	res, err := c.Post(data+"/submit", "text/plain", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	response, err := io.ReadAll(res.Body)
	_ = res.Body.Close()
	if err != nil || res.StatusCode != 201 || string(response) != "instrumented-origin" || calls.Load() != 1 || originBody.Load() != body {
		t.Fatalf("negative control: status=%d calls=%d err=%v", res.StatusCode, calls.Load(), err)
	}
	staged := revision(t, mustTool(t, c, adminURL, "stage_policy_revision", map[string]any{"bundle": bundle("late-body", "Body contains 'late-cli-deny'"), "idempotency_key": "stage-body"}))
	if got := revision(t, mustTool(t, c, adminURL, "get_policy_revision", map[string]any{})); got != initial {
		t.Fatalf("stage activated: %s", got)
	}
	mustTool(t, c, adminURL, "activate_policy_deployment", map[string]any{"revision": staged, "expected_revision": initial, "idempotency_key": "activate-body"})
	before := calls.Load()
	if err := post(c, data+"/submit", body); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != before {
		t.Fatal("blocked late body reached origin")
	}

	second := revision(t, mustTool(t, c, adminURL, "stage_policy_revision", map[string]any{"bundle": bundle("late-body-v2", "Body contains 'late-cli-deny' || Path == '/v2-only'"), "idempotency_key": "stage-body-v2"}))
	start := make(chan struct{})
	errs := make(chan error, 5)
	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for range 12 {
				if err := post(c, data+"/submit", body); err != nil {
					errs <- err
					return
				}
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-start
		_, err := tool(c, adminURL, "activate_policy_deployment", map[string]any{"revision": second, "expected_revision": staged, "idempotency_key": "reload-concurrent"})
		if err != nil {
			errs <- err
		}
	}()
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	if calls.Load() != before {
		t.Fatal("reload leaked blocked requests to origin")
	}
	if err := post(c, data+"/v2-only", ""); err != nil {
		t.Fatalf("second revision was not enforced: %v", err)
	}
	if calls.Load() != before {
		t.Fatal("second revision's path rule leaked to origin")
	}
	if _, err := tool(c, adminURL, "activate_policy_deployment", map[string]any{"revision": initial, "expected_revision": staged, "idempotency_key": "stale-reload"}); err == nil {
		t.Fatal("stale revision CAS accepted")
	}
	rolled := mustTool(t, c, adminURL, "rollback_policy_deployment", map[string]any{"expected_revision": second, "idempotency_key": "rollback-previous"})
	if revision(t, rolled) != staged {
		t.Fatalf("rollback did not select previous: %v", rolled)
	}
	if err := post(c, data+"/submit", body); err != nil {
		t.Fatal(err)
	}
	res, err = c.Post(data+"/v2-only", "text/plain", strings.NewReader("rollback-control"))
	if err != nil {
		t.Fatal(err)
	}
	_, readErr := io.Copy(io.Discard, res.Body)
	_ = res.Body.Close()
	if readErr != nil || res.StatusCode != 201 || calls.Load() != before+1 || originBody.Load() != "rollback-control" {
		t.Fatalf("rollback did not restore previous live behavior: status=%d calls=%d err=%v", res.StatusCode, calls.Load(), readErr)
	}
	before = calls.Load()
	p.stop(t)
	if out, err := runCLI(t, "", "healthcheck", "--url", adminURL+"/readyz"); err == nil {
		t.Fatalf("healthcheck succeeded after shutdown: %s", out)
	}

	p = startCLI(t, adminToken, args...)
	waitReady(t, p, c, adminURL+"/readyz")
	if got := revision(t, mustTool(t, c, adminURL, "get_policy_revision", map[string]any{})); got != staged {
		t.Fatalf("restart active=%s want=%s", got, staged)
	}
	if err := post(c, data+"/submit", body); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != before {
		t.Fatal("persisted policy failed to block after restart")
	}
	p.stop(t)
}

func TestShippingValidationAndStartupRejections(t *testing.T) {
	config, _ := runtimeConfig(t, "http://127.0.0.1:1", freeAddress(t, "tcp"))
	if out, err := runCLI(t, "", "version"); err != nil || !strings.Contains(out, `"version":"netcap-firewall/v1"`) {
		t.Fatalf("version: %v %s", err, out)
	}
	if out, err := runCLI(t, "", "validate", "--config", config); err != nil || !strings.Contains(out, "valid policy revision") {
		t.Fatalf("relative policy path: %v %s", err, out)
	}
	for _, tc := range []struct {
		name, token, want string
		args              []string
	}{
		{"missing-token", "", "managed mode requires NETCAP_FIREWALL_ADMIN_TOKEN", []string{"--managed", "--state-dir", filepath.Join(t.TempDir(), "state")}},
		{"short-token", "short", "at least 32 bytes", nil},
		{"missing-state", adminToken, "managed mode requires StateDir", []string{"--managed"}},
		{"unpaired-TLS", "", "must be paired", []string{"--admin-cert", "missing.pem"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			args := append([]string{"serve", "--config", config}, tc.args...)
			out, err := runCLI(t, tc.token, args...)
			if err == nil || !strings.Contains(out, tc.want) {
				t.Fatalf("wanted %q, got %v: %s", tc.want, err, out)
			}
		})
	}
	networkConfig, _ := runtimeConfig(t, "http://127.0.0.1:1", "0.0.0.0:0")
	if out, err := runCLI(t, adminToken, "serve", "--config", networkConfig); err == nil || !strings.Contains(out, "network-accessible policy management requires admin-cert and admin-key") {
		t.Fatalf("plaintext network admin: %v %s", err, out)
	}
	writeFile(t, filepath.Join(filepath.Dir(config), "policy.json"), `{"version":`)
	if out, err := runCLI(t, "", "validate", "--config", config); err == nil {
		t.Fatalf("malformed policy accepted: %s", out)
	}
	writeFile(t, config, `{"version":`)
	if out, err := runCLI(t, "", "validate", "--config", config); err == nil {
		t.Fatalf("malformed runtime accepted: %s", out)
	}
}

func TestShippingCorazaValidation(t *testing.T) {
	config, _ := runtimeConfig(t, "http://127.0.0.1:1", freeAddress(t, "tcp"))
	raw, err := os.ReadFile(config)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, config, strings.TrimSuffix(string(raw), "}")+`,"corazaCRS":true}`)
	out, err := runCLI(t, "", "validate", "--config", config)
	if cliBuildTags == "coraza" {
		if err != nil || !strings.Contains(out, "valid policy revision") {
			t.Fatalf("tagged Coraza validate: %v %s", err, out)
		}
	} else if err == nil || !strings.Contains(out, "corazaCRS requires a build with -tags coraza") {
		t.Fatalf("unsupported Coraza accepted: %v %s", err, out)
	}
}

func TestShippingDNSGateway(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int64
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 4096)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			calls.Add(1)
			response := append([]byte(nil), buf[:n]...)
			response[2], response[3] = 0x81, 0x80
			response[6], response[7] = 0, 1
			response = append(response, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4, 192, 0, 2, 1)
			_, _ = pc.WriteTo(response, addr)
		}
	}()
	t.Cleanup(func() { _ = pc.Close(); <-done })
	path := filepath.Join(t.TempDir(), "dns.json")
	writeFile(t, path, bundle("dns-cli", "Protocol == 'dns' && DNS.Name == 'blocked.test.'"))
	addr := freeAddress(t, "udp")
	p := startCLI(t, "", "gateway", "--protocol", "dns", "--listen", addr, "--upstream", pc.LocalAddr().String(), "--policy", path)
	exchange := func(name string) (dnsmessage.Message, error) {
		var reply dnsmessage.Message
		q := dnsmessage.Message{Header: dnsmessage.Header{ID: 42, RecursionDesired: true}, Questions: []dnsmessage.Question{{Name: dnsmessage.MustNewName(name), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}}}
		raw, err := q.Pack()
		if err != nil {
			return reply, err
		}
		conn, err := net.DialTimeout("udp", addr, time.Second)
		if err != nil {
			return reply, err
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(250 * time.Millisecond))
		if _, err = conn.Write(raw); err != nil {
			return reply, err
		}
		buf := make([]byte, 4096)
		n, err := conn.Read(buf)
		if err != nil {
			return reply, err
		}
		err = reply.Unpack(buf[:n])
		return reply, err
	}
	deadline := time.NewTimer(10 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(20 * time.Millisecond)
	defer tick.Stop()
	for {
		r, err := exchange("allowed.test.")
		if err == nil {
			if r.ID != 42 || r.RCode != dnsmessage.RCodeSuccess || len(r.Answers) != 1 {
				t.Fatalf("allowed DNS reply: %+v", r)
			}
			break
		}
		select {
		case <-p.done:
			t.Fatalf("gateway exited: %v %s", p.err, p.log.String())
		case <-deadline.C:
			t.Fatalf("gateway readiness: %v %s", err, p.log.String())
		case <-tick.C:
		}
	}
	before := calls.Load()
	if before == 0 {
		t.Fatal("allowed DNS negative control never reached origin")
	}
	r, err := exchange("blocked.test.")
	if err != nil || r.ID != 42 || r.RCode != dnsmessage.RCodeRefused {
		t.Fatalf("blocked DNS reply: %+v %v", r, err)
	}
	if calls.Load() != before {
		t.Fatal("blocked DNS reached origin")
	}
	p.stop(t)
}
