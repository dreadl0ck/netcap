//go:build unix

package firewallui

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/internal/enforcer"
	"github.com/dreadl0ck/netcap/internal/firewallauth"
	"github.com/dreadl0ck/netcap/internal/firewallfleet"
	"github.com/dreadl0ck/netcap/internal/policy"
	"github.com/dreadl0ck/netcap/internal/policycontrol"
	"github.com/dreadl0ck/netcap/internal/waf"
)

// Run manually with FIREWALL_PLAYWRIGHT_MODULE pointing at the existing locked
// @playwright/test module. No npm install, application env loader, or provider.
func TestBrowser(t *testing.T) {
	module := os.Getenv("FIREWALL_PLAYWRIGHT_MODULE")
	if module == "" {
		t.Skip("set FIREWALL_PLAYWRIGHT_MODULE for integration-local Chromium tests")
	}
	runID := "firewall-ui-" + time.Now().UTC().Format("20060102T150405.000000000")
	var originCalls atomic.Int32
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { originCalls.Add(1); w.WriteHeader(204) }))
	defer origin.Close()
	b, err := policy.Parse([]byte(`{"version":"1","id":"initial","mode":"enforce","default":"allow","rules":[]}`))
	if err != nil {
		t.Fatal(err)
	}
	compiled, err := policy.Compile(b)
	if err != nil {
		t.Fatal(err)
	}
	f, err := waf.New(waf.Config{Version: "netcap-firewall/v1", Listen: "127.0.0.1:8080", AdminListen: "127.0.0.1:8081", Upstream: origin.URL, MaxBodyBytes: 1024, MaxResponseBytes: 1024, MaxConcurrent: 8, BodyTimeout: "2s"}, compiled)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	traffic := httptest.NewServer(f)
	defer traffic.Close()
	token := strings.Repeat("synthetic-ui-", 4)
	cfg := policycontrol.Config{Token: token, Managed: true, StateDir: filepath.Join(t.TempDir(), "policy")}
	s, err := policycontrol.New(cfg, f)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	identity := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/fixture/identity" {
				_ = json.NewEncoder(w).Encode(map[string]any{"run_id": runID, "origin_calls": originCalls.Load(), "revision": f.Policy().Revision()})
				return
			}
			next.ServeHTTP(w, r)
		})
	}
	admin := httptest.NewServer(identity(Wrap(s.Handler(), "policy")))
	defer admin.Close()
	readonly, err := policycontrol.New(policycontrol.Config{Token: token}, f)
	if err != nil {
		t.Fatal(err)
	}
	defer readonly.Close()
	ro := httptest.NewServer(identity(Wrap(readonly.Handler(), "policy")))
	defer ro.Close()
	// The legacy fixtures above remain independent of the scoped identity console.
	authServer := httptest.NewUnstartedServer(nil)
	authOrigin := "http://" + authServer.Listener.Addr().String()
	authScope := firewallauth.Scope{Tenant: "browser", App: "web", Environment: "test", Target: "edge"}
	reader, err := firewallauth.New(firewallauth.Config{Static: []firewallauth.Static{{Token: token, Principal: firewallauth.Principal{ID: "reader", Grants: []firewallauth.Grant{{Scope: authScope, Actions: []firewallauth.Action{firewallauth.Read}}}}}}})
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	authService, err := policycontrol.New(policycontrol.Config{Auth: reader, Scope: authScope, Origin: authOrigin, Managed: true, StateDir: filepath.Join(t.TempDir(), "scoped-policy")}, f)
	if err != nil {
		t.Fatal(err)
	}
	defer authService.Close()
	authServer.Config.Handler = identity(WrapOrigin(authService.Handler(), "policy", authOrigin, true))
	authServer.Start()
	defer authServer.Close()
	scope := firewallfleet.Scope{Tenant: "tenant-a", App: "app"}
	fleet, err := firewallfleet.New(firewallfleet.Config{StateDir: filepath.Join(t.TempDir(), "fleet"), Token: token, Identities: []firewallfleet.Identity{{ID: "scoped", Token: "synthetic-scoped-token", Scope: scope}}, Targets: []firewallfleet.Enrollment{{ID: "edge-a", Token: "synthetic-agent-token", Scope: scope}, {ID: "foreign", Token: "synthetic-foreign-token", Scope: firewallfleet.Scope{Tenant: "tenant-b", App: "app"}}}})
	if err != nil {
		t.Fatal(err)
	}
	defer fleet.Close()
	fc := httptest.NewServer(identity(Wrap(fleet.Handler(), "fleet")))
	defer fc.Close()
	e, err := enforcer.New(enforcer.Config{Token: token, DryRun: true, Scope: enforcer.Scope{Hook: "input", Interface: "veth0", DestinationCIDR: "10.44.0.1/32", Protocol: "tcp", Port: 443}, StateFile: filepath.Join(t.TempDir(), "leases.json")}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	if _, err = e.Create(context.Background(), "fixture-lease", "198.51.100.1", time.Minute); err != nil {
		t.Fatal(err)
	}
	le := httptest.NewServer(identity(Wrap(e.Handler(), "leases")))
	defer le.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	artifacts, err := os.MkdirTemp("", runID+"-evidence-")
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(ctx, "node", "--test", "e2e/browser.cjs")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM) }
	cmd.WaitDelay = 2 * time.Second
	defer func() {
		if cmd.Process != nil {
			// The group belongs only to this invocation, including Chromium children.
			if err := syscall.Kill(-cmd.Process.Pid, 0); err == nil {
				_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
			}
		}
	}()
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME"), "TMPDIR=" + os.TempDir(), "FIREWALL_PLAYWRIGHT_MODULE=" + module, "UI_ORIGIN=" + admin.URL, "READONLY_ORIGIN=" + ro.URL, "FLEET_ORIGIN=" + fc.URL, "LEASE_ORIGIN=" + le.URL, "TRAFFIC_ORIGIN=" + traffic.URL, "AUTH_ORIGIN=" + authServer.URL, "RUN_ID=" + runID, "UI_TOKEN=" + token}
	if cache := os.Getenv("PLAYWRIGHT_BROWSERS_PATH"); cache != "" {
		cmd.Env = append(cmd.Env, "PLAYWRIGHT_BROWSERS_PATH="+cache)
	}
	cmd.Env = append(cmd.Env, "UI_ARTIFACTS="+artifacts)
	t.Logf("integration-local run=%s policy=%s readonly=%s fleet=%s leases=%s traffic=%s state=%s", runID, admin.URL, ro.URL, fc.URL, le.URL, traffic.URL, cfg.StateDir)
	out, err := cmd.CombinedOutput()
	t.Log(string(out))
	if err != nil {
		t.Logf("private synthetic failure traces: %s", artifacts)
		t.Fatalf("Chromium suite: %v", err)
	}
	defer os.RemoveAll(artifacts)
	// Reopen the real database after browser mutation; persistence must survive
	// service restart, not merely the browser's in-memory active label.
	revision := f.Policy().Revision()
	admin.Close()
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	f.SetPolicy(compiled)
	reopened, err := policycontrol.New(cfg, f)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if f.Policy().Revision() != revision {
		t.Fatal("active revision lost after database reopen")
	}
}
