package firewall

import (
	"bytes"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/internal/enforcer"
	"github.com/dreadl0ck/netcap/internal/firewallfleet"
	"github.com/dreadl0ck/netcap/internal/policy"
	"github.com/dreadl0ck/netcap/internal/waf"
)

func routedRuntimeFile(t *testing.T, dir, origin string, a, b policy.Bundle) (file, data, admin string) {
	t.Helper()
	file, data, admin = followRuntime(t, dir, origin)
	var cfg waf.Config
	raw, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatal(err)
	}
	for i, bundle := range []policy.Bundle{a, b} {
		id := []string{"a", "b"}[i]
		path := followJSON(t, filepath.Join(dir, id+".json"), bundle)
		cfg.Routes = append(cfg.Routes, waf.RouteConfig{ID: id, PolicyID: bundle.ID, PolicyFile: path, Hosts: []string{id + ".example"}, Methods: []string{"GET", "POST"}, PathPrefix: "/", Upstream: origin, MaxBodyBytes: 4096, MaxResponseBytes: 4096, MaxConcurrent: 8})
	}
	followJSON(t, file, cfg)
	return
}

func routedStatus(t *testing.T, c *http.Client, data, host, path, source string) int {
	t.Helper()
	r, _ := http.NewRequest("GET", "http://"+data+path, nil)
	r.Host = host + ".example"
	r.Header.Set("X-Forwarded-For", source)
	// Neither a header nor a duplicate bundle ID may choose the attachment.
	r.Header.Set("X-Route-ID", "a")
	resp, err := c.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode
}

func TestRoutedFleetEffectsAndForeignPolicyAdmissionCommand(t *testing.T) {
	const operator = "routed-operator-token-32-bytes-long"
	const agentToken = "routed-agent-token-32-bytes-long"
	const leaseToken = "routed-enforcer-token-32-bytes-long"
	t.Setenv("ROUTED_AGENT", agentToken)
	t.Setenv("ROUTED_ENFORCER", leaseToken)
	t.Setenv("NETCAP_FIREWALL_ADMIN_TOKEN", "")
	dir := t.TempDir()
	scope := firewallfleet.Scope{Tenant: "tenant-a", App: "app-a"}
	fleet, err := firewallfleet.New(firewallfleet.Config{StateDir: filepath.Join(dir, "fleet"), Token: operator, AllowEffects: true, Targets: []firewallfleet.Enrollment{{ID: "edge-a", Token: agentToken, Scope: scope}}})
	if err != nil {
		t.Fatal(err)
	}
	defer fleet.Close()
	var polls, ack atomic.Int64
	controller := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/fleet/ack" {
			raw, _ := io.ReadAll(r.Body)
			r.Body = io.NopCloser(bytes.NewReader(raw))
			var v firewallfleet.Ack
			_ = json.Unmarshal(raw, &v)
			ack.Store(v.Generation)
		}
		fleet.Handler().ServeHTTP(w, r)
		if r.URL.Path == "/api/v1/fleet/desired" {
			polls.Add(1)
		}
	}))
	defer controller.Close()
	network := enforcer.Scope{Hook: "forward", Interface: "eth0", DestinationCIDR: "10.1.0.0/24", Protocol: "tcp", Port: 443}
	e, err := enforcer.New(enforcer.Config{Token: leaseToken, Table: "netcap_firewall_routed_fixture", Scope: network, DryRun: true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	leaseAPI := httptest.NewTLSServer(e.Handler())
	defer leaseAPI.Close()
	ca := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaseAPI.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	effects := followJSON(t, filepath.Join(dir, "effects.json"), map[string]any{"ca": ca, "scopes": map[string]any{"edge": map[string]any{"endpoint": leaseAPI.URL, "tokenEnv": "ROUTED_ENFORCER", "network": network}}})
	agentDir := filepath.Join(dir, "agent")
	agent := followJSON(t, filepath.Join(dir, "agent.json"), map[string]any{"url": controller.URL, "tokenEnv": "ROUTED_AGENT", "targetID": "edge-a", "scope": scope, "stateDir": agentDir, "pollInterval": int64(20 * time.Millisecond), "allowEffects": true})
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	defer origin.Close()
	configDir := t.TempDir()
	config, data, admin := routedRuntimeFile(t, configDir, origin.URL, followPolicy("same-policy", "false", "edge"), followPolicy("same-policy", `Path == "/local"`, ""))
	p := followStart(t, "serve", "--config", config, "--route-id", "a", "--fleet-agent-config", agent, "--effects-config", effects)
	followListen(t, p, admin)
	c := followClient(t)
	ready := "http://" + admin + "/readyz"
	if followStatus(c, ready) != 503 || routedStatus(t, c, data, "a", "/", "192.0.2.10") != 503 || routedStatus(t, c, data, "b", "/", "192.0.2.11") != 204 {
		t.Fatal("cold fleet drained an unrelated route")
	}
	call := func(op string, input map[string]any) []byte {
		t.Helper()
		input["scope"] = scope
		code, raw := followRequest(t, c, "POST", controller.URL+"/api/v1/fleet/"+op, operator, input)
		if code != 200 {
			t.Fatalf("%s: %d %s", op, code, raw)
		}
		return raw
	}
	activate := func(job, id, expression, effect string, expected int) string {
		t.Helper()
		bundle, _ := json.Marshal(followPolicy(id, expression, effect))
		var staged map[string]string
		_ = json.Unmarshal(call("stage", map[string]any{"bundle": string(bundle)}), &staged)
		call("rollout", map[string]any{"id": job, "revision": staged["revision"], "targets": []string{"edge-a"}, "expected": map[string]int{"edge-a": expected}, "deadline": time.Now().Add(time.Minute)})
		call("activate", map[string]any{"id": job, "expected_phase": "staged"})
		return staged["revision"]
	}
	activate("first", "same-policy", `Path == "/effect"`, "edge", 0)
	followWait(t, p, func() bool { return ack.Load() == 1 && followStatus(c, ready) == 200 })
	if routedStatus(t, c, data, "b", "/effect", "192.0.2.11") != 204 || routedStatus(t, c, data, "b", "/local", "192.0.2.11") != 403 {
		t.Fatal("fleet replaced local route policy")
	}
	if leases, err := e.List(t.Context()); err != nil || len(leases) != 0 {
		t.Fatalf("local route submitted effects: %+v %v", leases, err)
	}
	if routedStatus(t, c, data, "a", "/effect", "192.0.2.10") != 403 {
		t.Fatal("route effect policy not active")
	}
	followWait(t, p, func() bool {
		leases, err := e.List(t.Context())
		return err == nil && len(leases) == 1 && leases[0].Source == "192.0.2.10"
	})
	foreign := activate("foreign", "other-policy", "true", "", 1)
	before := polls.Load()
	followWait(t, p, func() bool { return polls.Load() >= before+4 })
	if ack.Load() != 1 || routedStatus(t, c, data, "a", "/", "192.0.2.10") != 204 {
		t.Fatal("foreign policy activated or acknowledged")
	}
	cache, err := os.ReadFile(filepath.Join(agentDir, "agent-cache.json"))
	if err != nil || bytes.Contains(cache, []byte(foreign)) {
		t.Fatal("foreign route policy persisted")
	}
	// Selected policy files are no longer an authority after attachment ownership.
	followJSON(t, filepath.Join(configDir, "a.json"), followPolicy("other-policy", "true", ""))
	if err := p.cmd.Process.Signal(syscall.SIGHUP); err != nil {
		t.Fatal(err)
	}
	activate("second", "same-policy", `Path == "/next"`, "", 2)
	followWait(t, p, func() bool { return ack.Load() == 3 })
	if routedStatus(t, c, data, "a", "/next", "192.0.2.10") != 403 || routedStatus(t, c, data, "a", "/effect", "192.0.2.10") != 204 || routedStatus(t, c, data, "b", "/local", "192.0.2.11") != 403 {
		t.Fatal("policy change crossed immutable attachment")
	}
	call("revoke", map[string]any{"targets": []string{"edge-a"}, "expected": map[string]int{"edge-a": 3}})
	followWait(t, p, func() bool { return followStatus(c, ready) == 503 })
	if routedStatus(t, c, data, "a", "/", "192.0.2.10") != 503 || routedStatus(t, c, data, "b", "/", "192.0.2.11") != 204 {
		t.Fatal("revocation drained unrelated route")
	}
	p.stop(t)
}

func TestRoutedSharedStateAcrossProcessesAndLocalIsolation(t *testing.T) {
	for _, native := range []bool{false, true} {
		t.Run(map[bool]string{false: "rate", true: "native"}[native], func(t *testing.T) {
			const token = "routed-state-token-32-bytes-long"
			t.Setenv("ROUTED_STATE", token)
			t.Setenv("NETCAP_FIREWALL_ADMIN_TOKEN", "")
			dir := t.TempDir()
			addr := followAddr(t)
			serverConfig := followJSON(t, filepath.Join(dir, "state.json"), serviceFile{StateDir: filepath.Join(dir, "state"), Principals: []principalFile{{ID: "proxy", TokenEnv: "ROUTED_STATE", Scope: firewallfleet.Scope{Tenant: "tenant-a", App: "app-a"}}}})
			service, flag := "sharedstate", "--shared-rate-config"
			if native {
				service, flag = "policy-state", "--policy-state-config"
				followJSON(t, serverConfig, policyStateFile{StateDir: filepath.Join(dir, "state"), Principals: []principalFile{{ID: "proxy", TokenEnv: "ROUTED_STATE", Scope: firewallfleet.Scope{Tenant: "tenant-a", App: "app-a"}}}})
			}
			state := followStart(t, service, "--config", serverConfig, "--listen", addr)
			followListen(t, state, addr)
			clientCfg := map[string]any{"url": "http://" + addr, "tokenEnv": "ROUTED_STATE"}
			var traceMu sync.Mutex
			phases := map[string]int{}
			if native {
				upstream := followClient(t)
				trace := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					input, _ := io.ReadAll(r.Body)
					var evaluation struct {
						Event policy.Event `json:"event"`
					}
					_ = json.Unmarshal(input, &evaluation)
					out, _ := http.NewRequestWithContext(r.Context(), r.Method, "http://"+addr+r.URL.RequestURI(), bytes.NewReader(input))
					out.Header = r.Header.Clone()
					resp, err := upstream.Do(out)
					if err != nil {
						http.Error(w, "authority unavailable", 503)
						return
					}
					defer resp.Body.Close()
					raw, _ := io.ReadAll(resp.Body)
					if r.Method == "POST" {
						if evaluation.Event.Host != "a.example" || evaluation.Event.ClientIP != "192.0.2.20" {
							t.Errorf("authority received unbound host/source: %s %s", evaluation.Event.Host, evaluation.Event.ClientIP)
						}
						var decision policy.Decision
						if resp.StatusCode != 200 || json.Unmarshal(raw, &decision) != nil {
							t.Errorf("native authority: HTTP %d %s", resp.StatusCode, raw)
						}
						traceMu.Lock()
						phases[evaluation.Event.Phase]++
						traceMu.Unlock()
						t.Logf("native authority phase=%s event-status=%d: HTTP %d verdict=%s decision-status=%d", evaluation.Event.Phase, evaluation.Event.Status, resp.StatusCode, decision.Verdict, decision.Status)
					}
					for k, v := range resp.Header {
						w.Header()[k] = v
					}
					w.WriteHeader(resp.StatusCode)
					_, _ = w.Write(raw)
				}))
				defer trace.Close()
				clientCfg["url"] = trace.URL
			}
			if !native {
				clientCfg["id"] = "requests"
				clientCfg["window"] = int64(time.Minute)
				clientCfg["limit"] = 2
				clientCfg["unit"] = "request"
			}
			clientFile := followJSON(t, filepath.Join(dir, "client.json"), clientCfg)
			origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
			defer origin.Close()
			a := followPolicy("same-policy", "false", "")
			if native {
				a = followPolicy("same-policy", "true", "")
				a.Rules[0].Threshold = &policy.Threshold{Count: 3, Window: "1m", GroupBy: "ClientIP"}
			}
			b := followPolicy("same-policy", "false", "")
			c := followClient(t)
			var proxies []*followProcess
			var data, admin []string
			for i := 0; i < 2; i++ {
				file, d, m := routedRuntimeFile(t, t.TempDir(), origin.URL, a, b)
				p := followStart(t, "serve", "--config", file, "--route-id", "a", flag, clientFile)
				followListen(t, p, m)
				followWait(t, p, func() bool { return followStatus(c, "http://"+m+"/readyz") == 200 })
				proxies = append(proxies, p)
				data = append(data, d)
				admin = append(admin, m)
			}
			for i := 0; i < 6; i++ {
				if got := routedStatus(t, c, data[i%2], "b", "/", "192.0.2.20"); got != 204 {
					t.Fatalf("local route counted remotely: %d", got)
				}
			}
			for i, want := range []int{204, 204, 429} {
				if native && i == 2 {
					want = 403
				}
				if got := routedStatus(t, c, data[i%2], "a", "/", "192.0.2.20"); got != want {
					t.Fatalf("cross-process route count %d: got=%d want=%d", i, got, want)
				}
			}
			if native {
				traceMu.Lock()
				if phases["request"] != 3 || phases["response"] != 2 {
					t.Errorf("authority phase counts=%v; want 3 requests and 2 response decisions", phases)
				}
				traceMu.Unlock()
			}
			state.stop(t)
			for i, p := range proxies {
				followWait(t, p, func() bool { return followStatus(c, "http://"+admin[i]+"/readyz") == 503 })
				if routedStatus(t, c, data[i], "a", "/", "192.0.2.20") != 503 || routedStatus(t, c, data[i], "b", "/", "192.0.2.20") != 204 {
					t.Fatal("dependency outage leaked across route attachment")
				}
				p.stop(t)
			}
		})
	}
}
