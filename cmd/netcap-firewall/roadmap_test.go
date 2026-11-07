package main

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func jsonFile(t *testing.T, path string, value any) string {
	t.Helper()
	b, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, path, string(b))
	return path
}

func authenticated(t *testing.T, c *http.Client, method, url, token string, body any) (int, []byte) {
	t.Helper()
	var raw []byte
	if body != nil {
		var err error
		raw, err = json.Marshal(body)
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
	res, err := c.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	b, err := io.ReadAll(io.LimitReader(res.Body, 2<<20))
	if err != nil {
		t.Fatal(err)
	}
	return res.StatusCode, b
}

func waitListening(t *testing.T, p *process, addr string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			conn.Close()
			return
		}
		select {
		case <-p.done:
			t.Fatalf("server exited: %v %s", p.err, p.log.String())
		default:
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("listener unavailable: %s", p.log.String())
}

func status(t *testing.T, c *http.Client, url string) int {
	t.Helper()
	r, err := c.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Body.Close()
	io.Copy(io.Discard, r.Body)
	return r.StatusCode
}

func TestFleetTwoShippingTargetsAndOfflineRecovery(t *testing.T) {
	t.Setenv("CLI_FLEET_A", strings.Repeat("a", 32))
	t.Setenv("CLI_FLEET_B", strings.Repeat("b", 32))
	dir := t.TempDir()
	addr := freeAddress(t, "tcp")
	scope := map[string]string{"tenant": "demo", "app": "proxy"}
	config := jsonFile(t, filepath.Join(dir, "fleet.json"), map[string]any{"stateDir": filepath.Join(dir, "state"), "tokenEnv": "NETCAP_FIREWALL_ADMIN_TOKEN", "targets": []any{map[string]any{"id": "a", "tokenEnv": "CLI_FLEET_A", "scope": scope}, map[string]any{"id": "b", "tokenEnv": "CLI_FLEET_B", "scope": scope}}})
	controller := startCLI(t, adminToken, "fleet-controller", "--config", config, "--listen", addr)
	waitListening(t, controller, addr)
	c := httpClient(t)
	base := "http://" + addr
	call := func(op string, body map[string]any) []byte {
		t.Helper()
		body["scope"] = scope
		code, b := authenticated(t, c, "POST", base+"/api/v1/fleet/"+op, adminToken, body)
		if code != 200 {
			t.Fatalf("fleet %s: %d %s", op, code, b)
		}
		return b
	}
	raw := call("stage", map[string]any{"bundle": bundle("fleet-live", "Path == '/fleet-denied'")})
	var staged struct {
		Revision string `json:"revision"`
	}
	if err := json.Unmarshal(raw, &staged); err != nil || staged.Revision == "" {
		t.Fatalf("stage %s %v", raw, err)
	}
	call("rollout", map[string]any{"id": "deploy", "revision": staged.Revision, "targets": []string{"a", "b"}, "expected": map[string]int{"a": 0, "b": 0}, "deadline": time.Now().Add(time.Minute)})
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	defer origin.Close()
	targets := []*process{}
	urls := []string{}
	admins := []string{}
	for _, id := range []string{"a", "b"} {
		admin := freeAddress(t, "tcp")
		runtime, url := runtimeConfig(t, origin.URL, admin)
		path := jsonFile(t, filepath.Join(filepath.Dir(runtime), "agent.json"), map[string]any{"url": base, "tokenEnv": "CLI_FLEET_" + strings.ToUpper(id), "targetID": id, "scope": scope, "stateDir": filepath.Join(dir, "agent-"+id), "pollInterval": int64(20 * time.Millisecond)})
		p := startCLI(t, "", "serve", "--config", runtime, "--fleet-agent-config", path)
		waitListening(t, p, admin)
		if got := status(t, c, "http://"+admin+"/readyz"); got == 200 {
			t.Fatal("cold target trusted bootstrap policy")
		}
		targets = append(targets, p)
		urls = append(urls, url)
		admins = append(admins, admin)
	}
	call("activate", map[string]any{"id": "deploy", "expected_phase": "staged"})
	for i, p := range targets {
		waitReady(t, p, c, "http://"+admins[i]+"/readyz")
		if got := status(t, c, urls[i]+"/fleet-denied"); got != 403 {
			t.Fatalf("target %d did not enforce pushed policy: %d", i, got)
		}
		if got := status(t, c, urls[i]+"/ok"); got != 204 {
			t.Fatalf("target %d allowed status %d", i, got)
		}
		p.stop(t)
	}
	controller.stop(t)
	backup := filepath.Join(dir, "backups", "fleet-backup.sqlite")
	if out, err := runCLI(t, adminToken, "backup", "--service", "fleet", "--config", config, "--output", backup); err != nil {
		t.Fatalf("backup: %v %s", err, out)
	}
	restored := filepath.Join(dir, "restored")
	if out, err := runCLI(t, "", "restore", "--service", "fleet", "--input", backup, "--state-dir", restored); err != nil {
		t.Fatalf("restore: %v %s", err, out)
	}
	jsonFile(t, config, map[string]any{"stateDir": restored, "tokenEnv": "NETCAP_FIREWALL_ADMIN_TOKEN", "targets": []any{map[string]any{"id": "a", "tokenEnv": "CLI_FLEET_A", "scope": scope}, map[string]any{"id": "b", "tokenEnv": "CLI_FLEET_B", "scope": scope}}})
	recovered := startCLI(t, adminToken, "fleet-controller", "--config", config, "--listen", addr)
	waitListening(t, recovered, addr)
	code, body := authenticated(t, c, "GET", base+"/api/v1/fleet/desired", strings.Repeat("a", 32), nil)
	if code != 200 || !bytes.Contains(body, []byte(staged.Revision)) {
		t.Fatalf("restored desired: %d %s", code, body)
	}
	recovered.stop(t)
}

func TestSharedGuardAcrossTwoShippingOrigins(t *testing.T) {
	dir := t.TempDir()
	addr := freeAddress(t, "tcp")
	scope := map[string]string{"tenant": "demo", "app": "shared"}
	config := jsonFile(t, filepath.Join(dir, "state.json"), map[string]any{"stateDir": filepath.Join(dir, "db"), "principals": []any{map[string]any{"id": "proxies", "tokenEnv": "NETCAP_FIREWALL_ADMIN_TOKEN", "scope": scope}}})
	s := startCLI(t, adminToken, "sharedstate", "--config", config, "--listen", addr)
	waitListening(t, s, addr)
	rate := jsonFile(t, filepath.Join(dir, "rate.json"), map[string]any{"url": "http://" + addr, "tokenEnv": "NETCAP_FIREWALL_ADMIN_TOKEN", "id": "global", "window": int64(time.Minute), "limit": 2})
	c := httpClient(t)
	proxies := []*process{}
	urls := []string{}
	for range 2 {
		origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
		defer origin.Close()
		admin := freeAddress(t, "tcp")
		cfg, url := runtimeConfig(t, origin.URL, admin)
		p := startCLI(t, adminToken, "serve", "--config", cfg, "--legacy-admin", "--shared-rate-config", rate)
		waitReady(t, p, c, "http://"+admin+"/readyz")
		proxies = append(proxies, p)
		urls = append(urls, url)
	}
	for i, want := range []int{204, 204, 429, 429} {
		if got := status(t, c, urls[i%2]+"/ok"); got != want {
			t.Fatalf("shared request %d: %d want %d", i, got, want)
		}
	}
	for _, p := range proxies {
		p.stop(t)
	}
	s.stop(t)
	backup := filepath.Join(dir, "backups", "state-backup.sqlite")
	if out, err := runCLI(t, adminToken, "backup", "--service", "sharedstate", "--config", config, "--output", backup); err != nil {
		t.Fatalf("state backup: %v %s", err, out)
	}
	if out, err := runCLI(t, "", "restore", "--service", "sharedstate", "--input", backup, "--state-dir", filepath.Join(dir, "restored")); err != nil {
		t.Fatalf("state restore: %v %s", err, out)
	}
}

func testCertificate(t *testing.T) (cert, key string) {
	t.Helper()
	dir := t.TempDir()
	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "CLI integration"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IsCA: true, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &private.PublicKey, private)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := x509.MarshalECPrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	cert = filepath.Join(dir, "cert.pem")
	key = filepath.Join(dir, "key.pem")
	writeFile(t, cert, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})))
	writeFile(t, key, string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: encoded})))
	return
}

func TestEffectsBrokerShippingDryRunLease(t *testing.T) {
	dir := t.TempDir()
	cert, key := testCertificate(t)
	addr := freeAddress(t, "tcp")
	e := startCLI(t, adminToken, "enforcer", "--legacy-admin", "--listen", addr, "--interface", "eth0", "--destination", "10.1.0.0/24", "--port", "443", "--dry-run", "--tls-cert", cert, "--tls-key", key)
	waitListening(t, e, addr)
	network := map[string]any{"hook": "forward", "interface": "eth0", "destination_cidr": "10.1.0.0/24", "protocol": "tcp", "port": 443}
	effects := jsonFile(t, filepath.Join(dir, "effects.json"), map[string]any{"ca": cert, "scopes": map[string]any{"edge": map[string]any{"endpoint": "https://" + addr, "tokenEnv": "NETCAP_FIREWALL_ADMIN_TOKEN", "network": network}}})
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	defer origin.Close()
	admin := freeAddress(t, "tcp")
	cfg, url := runtimeConfig(t, origin.URL, admin)
	var runtime map[string]any
	// Use an explicitly trusted local reverse proxy boundary for attributed source.
	runtime = map[string]any{"version": "netcap-firewall/v1", "listen": strings.TrimPrefix(url, "http://"), "adminListen": admin, "upstream": origin.URL, "policyFile": "policy.json", "maxBodyBytes": 1048576, "maxResponseBytes": 1048576, "maxConcurrent": 32, "bodyTimeout": "5s", "trustedProxyCIDRs": []string{"127.0.0.0/8"}}
	jsonFile(t, cfg, runtime)
	policy := `{"version":"1","id":"effects-live","mode":"enforce","default":"allow","rules":[{"id":"deny","expression":"Path == '/effect'","action":"deny","effects":[{"kind":"block_source","target":"client","duration":"10s","scope":"edge"}]}]}`
	writeFile(t, filepath.Join(filepath.Dir(cfg), "policy.json"), policy)
	if out, err := runCLI(t, adminToken, "validate", "--config", cfg); err == nil {
		t.Fatalf("effects admitted without broker: %s", out)
	}
	p := startCLI(t, adminToken, "serve", "--config", cfg, "--legacy-admin", "--managed", "--state-dir", filepath.Join(dir, "managed"), "--effects-config", effects)
	c := httpClient(t)
	waitReady(t, p, c, "http://"+admin+"/readyz")
	request, err := http.NewRequest("GET", url+"/effect", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("X-Forwarded-For", "192.0.2.33")
	res, err := c.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != 403 {
		t.Fatalf("effect verdict %d", res.StatusCode)
	}
	pool := x509.NewCertPool()
	rawCert, err := os.ReadFile(cert)
	if err != nil {
		t.Fatal(err)
	}
	pool.AppendCertsFromPEM(rawCert)
	leaseClient := tlsHTTPClient(t, pool)
	deadline := time.Now().Add(5 * time.Second)
	for {
		code, b := authenticated(t, leaseClient, "GET", "https://"+addr+"/v1/leases", adminToken, nil)
		if code == 200 && bytes.Contains(b, []byte("192.0.2.33")) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("broker did not deliver lease: %d %s; %s", code, b, p.log.String())
		}
		time.Sleep(20 * time.Millisecond)
	}
	// The same admission gate must apply to immutable management compilation.
	initial := revision(t, mustTool(t, c, "http://"+admin, "get_policy_revision", map[string]any{}))
	staged := revision(t, mustTool(t, c, "http://"+admin, "stage_policy_revision", map[string]any{"bundle": strings.ReplaceAll(policy, "effects-live", "effects-managed"), "idempotency_key": "effects-stage"}))
	mustTool(t, c, "http://"+admin, "activate_policy_deployment", map[string]any{"revision": staged, "expected_revision": initial, "idempotency_key": "effects-activate"})
	p.stop(t)
	writeFile(t, filepath.Join(filepath.Dir(cfg), "policy.json"), bundle("safe-bootstrap", "false"))
	restarted := startCLI(t, adminToken, "serve", "--config", cfg, "--legacy-admin", "--managed", "--state-dir", filepath.Join(dir, "managed"), "--effects-config", effects)
	waitReady(t, restarted, c, "http://"+admin+"/readyz")
	if got := revision(t, mustTool(t, c, "http://"+admin, "get_policy_revision", map[string]any{})); got != staged {
		t.Fatalf("effect admission lost on recovery: %s", got)
	}
	restarted.stop(t)
	if out, err := runCLI(t, adminToken, "serve", "--config", cfg, "--legacy-admin", "--managed", "--state-dir", filepath.Join(dir, "managed")); err == nil {
		t.Fatalf("effect revision recovered without broker: %s", out)
	}
	e.stop(t)
	if strings.Contains(p.log.String(), adminToken) || strings.Contains(e.log.String(), adminToken) {
		t.Fatal("token leaked")
	}
}

func TestGatewayShippingProtocolInventoryAndLimits(t *testing.T) {
	dir := t.TempDir()
	policy := filepath.Join(dir, "policy.json")
	writeFile(t, policy, bundle("gateways", "Method == 'FLUSHALL'"))
	cert, key := testCertificate(t)
	for _, protocol := range []string{"redis", "postgres", "smtp", "dns-tcp", "dns-tls", "modbus"} {
		t.Run(protocol, func(t *testing.T) {
			addr := freeAddress(t, "tcp")
			args := []string{"gateway", "--protocol", protocol, "--listen", addr, "--upstream", "127.0.0.1:9", "--policy", policy, "--max-connections", "2", "--max-message-bytes", "4096", "--max-session-messages", "4", "--max-state-entries", "4", "--idle-timeout", "1s", "--io-timeout", "1s", "--session-timeout", "5s"}
			if protocol == "dns-tls" {
				args = append(args, "--tls-cert", cert, "--tls-key", key)
			}
			p := startCLI(t, "", args...)
			waitListening(t, p, addr)
			p.stop(t)
		})
	}
	base := []string{"gateway", "--protocol", "redis", "--listen", freeAddress(t, "tcp"), "--upstream", "127.0.0.1:9", "--policy", policy}
	for _, extra := range [][]string{{"--max-message-bytes", "1"}, {"--client-ca", cert}, {"--upstream-tls"}} {
		if out, err := runCLI(t, "", append(append([]string{}, base...), extra...)...); err == nil {
			t.Fatalf("invalid gateway resource/TLS accepted: %s", out)
		}
	}
}

func TestRedisShippingPolicyBlocksBeforeOrigin(t *testing.T) {
	origin, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer origin.Close()
	var dials atomic.Int64
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			c, err := origin.Accept()
			if err != nil {
				return
			}
			dials.Add(1)
			c.Close()
		}
	}()
	t.Cleanup(func() { origin.Close(); <-done })
	path := filepath.Join(t.TempDir(), "policy.json")
	writeFile(t, path, bundle("redis-wire", "Method == 'FLUSHALL'"))
	addr := freeAddress(t, "tcp")
	p := startCLI(t, "", "gateway", "--protocol", "redis", "--listen", addr, "--upstream", origin.Addr().String(), "--policy", path)
	waitListening(t, p, addr)
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(3 * time.Second))
	fmt.Fprint(c, "*1\r\n$8\r\nFLUSHALL\r\n")
	line, err := bufio.NewReader(c).ReadString('\n')
	if err != nil || !strings.Contains(line, "NOPERM") {
		t.Fatalf("Redis denial: %q %v", line, err)
	}
	if dials.Load() != 0 {
		t.Fatal("denied command dialed origin")
	}
	c.Close()
	p.stop(t)
}

func TestNetworkCLIAndStrictBootstrap(t *testing.T) {
	dir := t.TempDir()
	policy := filepath.Join(dir, "policy.json")
	writeFile(t, policy, bundle("network", "Network.DstPort == 443 && TLS.ServerName == 'blocked.example'"))
	args := []string{"network", "--policy", policy, "--namespace", "cli-lab", "--interface", "eth0", "--protected-cidr", "10.1.0.0/24", "--management-destination", "192.0.2.0/24", "--hook", "forward", "--failure-verdict", "deny", "--inspect-tls", "--validate-only"}
	if out, err := runCLI(t, "", args...); err != nil {
		t.Fatalf("network config: %v %s", err, out)
	}
	if out, err := runCLI(t, "", append(args, "--queue", "65536")...); err == nil {
		t.Fatalf("queue truncation accepted %s", out)
	}
	for _, body := range []string{`{"stateDir":"x","stateDir":"y"}`, `{"stateDir":"x","token":"secret"}`, `{"stateDir":"x"} {}`, strings.Repeat(" ", 1<<20) + `{}`} {
		path := filepath.Join(dir, "bad.json")
		writeFile(t, path, body)
		if out, err := runCLI(t, adminToken, "fleet-controller", "--config", path); err == nil {
			t.Fatalf("invalid bootstrap accepted %s", out)
		}
	}
	if out, err := runCLI(t, adminToken, "sharedstate", "--config", filepath.Join(dir, "missing"), "--listen", "0.0.0.0:9092"); err == nil || !strings.Contains(out, "requires TLS") {
		t.Fatalf("control TLS gate: %v %s", err, out)
	}
}

func tlsHTTPClient(t *testing.T, pool *x509.CertPool) *http.Client {
	t.Helper()
	c := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool}}}
	t.Cleanup(c.CloseIdleConnections)
	return c
}
