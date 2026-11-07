package main

import (
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
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/internal/firewallstate"
	"github.com/dreadl0ck/netcap/internal/policy"
	"github.com/dreadl0ck/netcap/internal/policystate"
)

func TestCLINativePolicyStateAcrossProxiesAndRestart(t *testing.T) {
	t.Setenv("NCF_NATIVE_CLI_TOKEN", adminToken)
	dir := t.TempDir()
	address := freeAddress(t, "tcp")
	config := filepath.Join(dir, "authority.json")
	writeFile(t, config, `{"stateDir":`+quoted(filepath.Join(dir, "state"))+`,"principals":[{"id":"proxy","tokenEnv":"NCF_NATIVE_CLI_TOKEN","scope":{"tenant":"tenant","app":"web"}}]}`)
	service := startCLI(t, "", "policy-state", "--config", config, "--listen", address)
	native, err := policystate.NewClient(policystate.ClientConfig{URL: "http://" + address, Token: adminToken})
	if err != nil {
		t.Fatal(err)
	}
	defer native.Close()
	deadline := time.Now().Add(15 * time.Second)
	for native.Probe(context.Background()) != nil {
		if time.Now().After(deadline) {
			t.Fatal("native CLI authority not ready", service.log.String())
		}
		time.Sleep(20 * time.Millisecond)
	}
	clientCfg := filepath.Join(dir, "client.json")
	writeFile(t, clientCfg, `{"url":`+quoted("http://"+address)+`,"tokenEnv":"NCF_NATIVE_CLI_TOKEN"}`)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("upstream")) }))
	defer upstream.Close()
	policy := `{"version":"1","id":"global","mode":"enforce","default":"allow","rules":[{"id":"rate","phase":"request","expression":"Method == 'GET'","action":"deny","threshold":{"mode":"sliding","count":3,"window":"1h","group_by":"ClientIP"}}]}`
	httpc := httpClient(t)
	var urls []string
	for i := 0; i < 2; i++ {
		admin := freeAddress(t, "tcp")
		runtime, data := runtimeConfig(t, upstream.URL, admin)
		writeFile(t, filepath.Join(filepath.Dir(runtime), "policy.json"), policy)
		proxy := startCLI(t, "", "serve", "--config", runtime, "--policy-state-config", clientCfg)
		waitReady(t, proxy, httpc, "http://"+admin+"/readyz")
		urls = append(urls, data)
	}
	get := func(url string, want int) {
		t.Helper()
		r, err := httpc.Get(url)
		if err != nil {
			t.Fatal(err)
		}
		defer r.Body.Close()
		_, _ = io.Copy(io.Discard, r.Body)
		if r.StatusCode != want {
			t.Fatalf("%s status %d want %d", url, r.StatusCode, want)
		}
	}
	get(urls[0]+"/one", 200)
	get(urls[1]+"/two", 200)
	get(urls[0]+"/three", 403)
	service.stop(t)
	// The data plane must deny explicitly rather than evaluate empty local state.
	get(urls[1]+"/partition", 503)
	backup := filepath.Join(t.TempDir(), "private", "snapshot.sqlite")
	if out, err := runCLI(t, "", "backup", "--service", "policy-state", "--config", config, "--output", backup); err != nil {
		t.Fatal(err, out)
	}
	if _, err := os.Stat(backup); err != nil {
		t.Fatal(err)
	}
	service = startCLI(t, "", "policy-state", "--config", config, "--listen", address)
	deadline = time.Now().Add(15 * time.Second)
	for native.Probe(context.Background()) != nil {
		if time.Now().After(deadline) {
			t.Fatal("native authority restart failed", service.log.String())
		}
		time.Sleep(20 * time.Millisecond)
	}
	get(urls[1]+"/after-restart", 403)
	service.stop(t)
}

func quoted(value string) string { raw, _ := json.Marshal(value); return string(raw) }

func TestCLIPostgresNativeStateReplicas(t *testing.T) {
	raw := os.Getenv("NETCAP_POSTGRES_TEST_URL")
	if raw == "" {
		if os.Getenv("NETCAP_POLICY_STATE_DOCKER") != "1" {
			t.Skip("NETCAP_POSTGRES_TEST_URL or NETCAP_POLICY_STATE_DOCKER=1 required")
		}
		docker := func(args ...string) string {
			t.Helper()
			ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
			defer cancel()
			out, err := exec.CommandContext(ctx, "docker", args...).CombinedOutput()
			if err != nil {
				t.Fatalf("docker %s: %s", args[0], out)
			}
			return strings.TrimSpace(string(out))
		}
		id := docker("run", "--rm", "-d", "-e", "POSTGRES_PASSWORD=ncf-cli-native", "-e", "POSTGRES_DB=native", "-p", "127.0.0.1::5432", "postgres:17.7-alpine")
		t.Cleanup(func() {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if out, err := exec.CommandContext(ctx, "docker", "rm", "-f", id).CombinedOutput(); err != nil {
				t.Errorf("PostgreSQL cleanup: %v %s", err, out)
			}
		})
		raw = "postgres://postgres:ncf-cli-native@" + docker("port", id, "5432/tcp") + "/native?sslmode=disable"
		deadline := time.Now().Add(15 * time.Second)
		ready := false
		for time.Now().Before(deadline) {
			if exec.Command("docker", "exec", id, "pg_isready", "-h", "127.0.0.1", "-U", "postgres", "-d", "native").Run() == nil {
				ready = true
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
		if !ready {
			t.Fatal("PostgreSQL CLI fixture not ready")
		}
	}
	u, err := url.Parse(raw)
	if err != nil || !net.ParseIP(u.Hostname()).IsLoopback() {
		t.Fatal("PostgreSQL CLI tests require literal loopback")
	}
	namespace := fmt.Sprintf("cli_native_%x", time.Now().UnixNano())
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		d, err := firewallstate.OpenPostgres(ctx, raw, namespace)
		if err != nil {
			t.Error(err)
			return
		}
		defer d.Close()
		if _, err := d.DB.ExecContext(ctx, `DROP SCHEMA "`+namespace+`" CASCADE`); err != nil {
			t.Error(err)
		}
	})
	t.Setenv("NCF_NATIVE_CLI_DB", raw)
	t.Setenv("NCF_NATIVE_CLI_TOKEN", adminToken)
	file := filepath.Join(t.TempDir(), "authority.json")
	writeFile(t, file, `{"databaseURLEnv":"NCF_NATIVE_CLI_DB","databaseNamespace":`+quoted(namespace)+`,"principals":[{"id":"proxy","tokenEnv":"NCF_NATIVE_CLI_TOKEN","scope":{"tenant":"tenant","app":"web"}}]}`)
	var clients []*policystate.Client
	var processes []*process
	for n := 0; n < 2; n++ {
		addr := freeAddress(t, "tcp")
		p := startCLI(t, "", "policy-state", "--config", file, "--listen", addr)
		processes = append(processes, p)
		c, err := policystate.NewClient(policystate.ClientConfig{URL: "http://" + addr, Token: adminToken})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(c.Close)
		deadline := time.Now().Add(15 * time.Second)
		for c.Probe(context.Background()) != nil {
			if time.Now().After(deadline) {
				t.Fatal("PG CLI authority unavailable", p.log.String())
			}
			time.Sleep(20 * time.Millisecond)
		}
		clients = append(clients, c)
	}
	p, err := policy.Compile(policy.Bundle{Version: "1", ID: "cli-shared", Mode: "enforce", Default: "allow", Rules: []policy.Rule{{ID: "distinct", Action: "deny", Expression: "true", Threshold: &policy.Threshold{Mode: "sliding", Count: 2, Window: "1m", Distinct: "Network.DstPort", GroupBy: "ClientIP"}}}})
	if err != nil {
		t.Fatal(err)
	}
	e := policy.Event{ClientIP: "192.0.2.5", Network: policy.NetworkEvent{DstPort: 443}}
	if d, err := clients[0].Evaluate(context.Background(), p, e); err != nil || d.Verdict != "allow" {
		t.Fatal(d, err)
	}
	e.Network.DstPort = 8443
	if d, err := clients[1].Evaluate(context.Background(), p, e); err != nil || d.Verdict != "deny" {
		t.Fatal("shipping authorities did not coordinate distinct state", d, err)
	}
	for _, process := range processes {
		process.stop(t)
	}
}
