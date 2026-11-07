//go:build linux

package appliance

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/internal/firewallauth"
	"github.com/dreadl0ck/netcap/internal/networkfirewall"
	"github.com/dreadl0ck/netcap/internal/transparentfirewall"
	"golang.org/x/sys/unix"
)

type labVerdict string

func TestApplianceProductionLab(t *testing.T) {
	if os.Getenv("NETCAP_APPLIANCE_LAB") != "1" {
		t.Skip("disposable Docker lab only")
	}
	if _, err := os.Stat("/.dockerenv"); err != nil {
		t.Fatal("Docker-only test")
	}
	m := fixture(t)
	m.Mode, m.TargetID = "production", "edge-a"
	p, err := m.Plan()
	if err != nil {
		t.Fatal(err)
	}
	dir := "/var/lib/nca-production"
	if _, err = Execute(context.Background(), m, dir, "apply"); err == nil {
		t.Fatal("production without bootstrap grant admitted")
	}
	if _, err = os.Stat(dir); !os.IsNotExist(err) {
		t.Fatal("authorization failure wrote state")
	}
	s := firewallauth.Scope{Tenant: "test", App: "network", Environment: "production", Target: m.TargetID}
	ctx := WithBootstrap(firewallauth.WithPrincipal(context.Background(), firewallauth.Principal{ID: "operator", Grants: []firewallauth.Grant{{Scope: s, Actions: []firewallauth.Action{firewallauth.Deploy}}}}), Bootstrap{Scope: s, ReviewedDigest: p.Digest})
	if _, err = Execute(ctx, m, dir, "apply"); err != nil {
		t.Fatal(err)
	}
	libraryRemoved := false
	t.Cleanup(func() {
		if libraryRemoved {
			return
		}
		if _, err := Execute(ctx, m, dir, "remove"); err != nil {
			t.Error(err)
		}
	})
	if _, err = Execute(ctx, m, dir, "recover"); err != nil {
		t.Fatal(err)
	}
	if _, err = Execute(ctx, m, dir, "status"); err != nil {
		t.Fatal(err)
	}
	if _, err = Execute(ctx, m, dir, "remove"); err != nil {
		t.Fatal(err)
	}
	libraryRemoved = true
	manifest, _ := json.Marshal(m)
	if err = os.WriteFile("/var/lib/nca-production-manifest.json", manifest, 0600); err != nil {
		t.Fatal(err)
	}
	bootstrap, _ := json.Marshal(map[string]any{"stateDir": "/var/lib/nca-production-auth", "scope": s, "static": []any{map[string]any{"tokenEnv": "NCA_OPERATOR_TOKEN", "principal": firewallauth.Principal{ID: "operator", Grants: []firewallauth.Grant{{Scope: s, Actions: []firewallauth.Action{firewallauth.Deploy}}}}}}})
	if err = os.WriteFile("/var/lib/nca-production-auth.json", bootstrap, 0600); err != nil {
		t.Fatal(err)
	}
	cli := func(action, digest string) error {
		c := exec.Command(os.Getenv("TFW_GATEWAY_BINARY"), "appliance", action, "--manifest", "/var/lib/nca-production-manifest.json", "--state-dir", "/var/lib/nca-production-cli", "--auth-config", "/var/lib/nca-production-auth.json", "--operator-token-env", "NCA_OPERATOR_TOKEN", "--reviewed-plan-digest", digest)
		c.Env = append(os.Environ(), "NCA_OPERATOR_TOKEN=synthetic-production-operator-token")
		out, e := c.CombinedOutput()
		if e != nil {
			return fmt.Errorf("CLI %s: %w: %s", action, e, out)
		}
		return nil
	}
	if cli("apply", "incorrect") == nil {
		t.Fatal("CLI accepted unreviewed production manifest")
	}
	for _, action := range []string{"apply", "recover", "status", "remove"} {
		if err := cli(action, p.Digest); err != nil {
			t.Fatal(err)
		}
	}
	t.Log("production authorization and reviewed digest exercised only in disposable Docker namespaces")
}

func (v labVerdict) EvaluatePacket(networkfirewall.PacketEvent) (networkfirewall.Decision, error) {
	return networkfirewall.Decision{Verdict: networkfirewall.Verdict(v)}, nil
}

func TestApplianceHelper(t *testing.T) {
	mode := os.Getenv("NCA_HELPER")
	if mode == "" {
		return
	}
	var m Manifest
	if e := json.Unmarshal([]byte(os.Getenv("NCA_MANIFEST")), &m); e != nil {
		t.Fatal(e)
	}
	if mode == "crash" || mode == "crash-remove" {
		command = func(ctx context.Context, args ...string) ([]byte, error) {
			b, e := runCommand(ctx, args...)
			if e == nil && strings.Contains(strings.Join(args, " "), os.Getenv("NCA_CRASH_AFTER")) {
				_ = unix.Kill(os.Getpid(), unix.SIGKILL)
			}
			return b, e
		}
		action := "apply"
		if mode == "crash-remove" {
			action = "remove"
		}
		if _, e := Execute(context.Background(), m, os.Getenv("NCA_STATE"), action); e != nil {
			t.Fatal(e)
		}
		t.Fatal("crash injection missed resource write")
	}
	c := m.NetworkConfig()
	c.RecoverOwned = true
	f, e := networkfirewall.New(c, labVerdict(mode))
	if e != nil {
		t.Fatal(e)
	}
	go func() { <-f.Ready(); p := os.NewFile(3, "ready"); _, _ = p.Write([]byte{1}); _ = p.Close() }()
	if e = f.Run(context.Background()); e != nil {
		t.Fatal(e)
	}
}

func TestApplianceCrashLab(t *testing.T) {
	if os.Getenv("NETCAP_APPLIANCE_LAB") != "1" {
		t.Skip("disposable Docker lab only")
	}
	ctx := context.Background()
	m := fixture(t)
	exe, e := os.Executable()
	if e != nil {
		t.Fatal(e)
	}
	encoded, _ := json.Marshal(m)
	for i, after := range []string{"link set lo alias", "link add c0 address", "addr add 10.180.0.2/24", "route add 10.181.0.0/24"} {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			dir := fmt.Sprintf("/var/lib/nca-crash-%d", i)
			c := exec.Command(exe, "-test.run=^TestApplianceHelper$")
			c.Env = append(os.Environ(), "NCA_HELPER=crash", "NCA_MANIFEST="+string(encoded), "NCA_STATE="+dir, "NCA_CRASH_AFTER="+after)
			if b, e := c.CombinedOutput(); e == nil {
				t.Fatalf("writer not killed: %s", b)
			}
			j, e := os.ReadFile(dir + "/desired.json")
			if e != nil {
				t.Fatal(e)
			}
			var record journal
			if e = json.Unmarshal(j, &record); e != nil {
				t.Fatal(e)
			}
			if record.Pending == "" {
				t.Fatal("write-ahead intent not durable")
			}
			if _, e = Execute(ctx, m, dir, "recover"); e != nil {
				t.Fatal("crash recovery:", e)
			}
			// Foreign resources must prevent rollback before any owned namespace
			// is deleted, even after a partially completed bootstrap.
			_, e = scoped(ctx, "nca-client", "ip", "link", "add", "foreign0", "type", "dummy")
			if e != nil {
				t.Fatal(e)
			}
			if _, e = Execute(ctx, m, dir, "remove"); e == nil {
				t.Fatal("foreign interface destroyed")
			}
			if _, e = scoped(ctx, "nca-client", "ip", "link", "show", "foreign0"); e != nil {
				t.Fatal(e)
			}
			_, _ = scoped(ctx, "nca-client", "ip", "link", "del", "foreign0")
			if _, e = Execute(ctx, m, dir, "remove"); e != nil {
				t.Fatal(e)
			}
		})
	}
}

func TestApplianceGatewayLab(t *testing.T) {
	if os.Getenv("NETCAP_APPLIANCE_LAB") != "1" {
		t.Skip("disposable Docker lab only")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m := fixture(t)
	dir := "/var/lib/nca-gateway-test"
	if _, err := Execute(ctx, m, dir, "apply"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := Execute(context.Background(), m, dir, "remove"); err != nil {
			t.Error(err)
		}
	})
	f, err := networkfirewall.New(func() networkfirewall.Config {
		c := m.NetworkConfig()
		c.RecoverOwned = true
		return c
	}(), labVerdict("allow"))
	if err != nil {
		t.Fatal(err)
	}
	finished := make(chan error, 1)
	go func() { finished <- f.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		if err := <-finished; err != nil {
			t.Error(err)
		}
	})
	select {
	case <-f.Ready():
	case err := <-finished:
		finished <- err
		t.Fatal(err)
	case <-time.After(5 * time.Second):
		t.Fatal("packet listener not ready")
	}
	start := func(namespace string, args ...string) *exec.Cmd {
		t.Helper()
		c := exec.Command("ip", append([]string{"netns", "exec", namespace}, args...)...)
		c.Env = os.Environ()
		c.Stdout, c.Stderr = os.Stdout, os.Stderr
		return c
	}
	spawn := func(c *exec.Cmd) {
		t.Helper()
		if err := c.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = c.Process.Kill(); _ = c.Wait() })
	}
	log := t.TempDir() + "/origin"
	origin := start("nca-origin", "/transparentfirewall.test", "-test.run=^TestPlacementHelper$")
	origin.Env = append(origin.Env, "TFW_ROLE=origin", "TFW_PROTOCOL=redis", "TFW_ADDRESS=[::]:6379", "TFW_LOG="+log)
	spawn(origin)
	for _, family := range []struct{ service, gateway, upstreamPeer string }{
		{"10.181.0.2", "10.180.0.1", "10.181.0.1"}, {"fd81::2", "fd80::1", "fd81::1"},
	} {
		t.Run(family.service, func(t *testing.T) {
			c := transparentfirewall.Config{NetworkNamespace: m.Packet.Namespace, IngressInterface: m.Packet.Interface, OriginalService: family.service, OriginalPort: 6379, GatewayPort: 16379, Protocol: "redis", TLSMode: "plaintext"}
			if cleanup, err := transparentfirewall.Install(ctx, c); err == nil {
				_ = cleanup()
				t.Fatal("DNAT admitted before gateway listener")
			}
			policy := t.TempDir() + "/policy.json"
			bundle := `{"version":"1","id":"appliance-gateway","mode":"enforce","default":"allow","rules":[{"id":"identity","action":"deny","expression":"ClientIP != '10.180.0.2' && ClientIP != 'fd80::2'"},{"id":"write","action":"deny","expression":"Method == 'FLUSHALL'"}]}`
			if err := os.WriteFile(policy, []byte(bundle), 0600); err != nil {
				t.Fatal(err)
			}
			gateway := start(m.Packet.Namespace, "/firewall", "gateway", "--protocol", "redis", "--listen", net.JoinHostPort(family.gateway, "16379"), "--upstream", net.JoinHostPort(family.service, "6379"), "--policy", policy, "--allow-client", "10.180.0.2/32", "--allow-client", "fd80::2/128", "--io-timeout", "1s")
			spawn(gateway)
			var cleanup func() error
			var err error
			for i := 0; i < 100; i++ {
				cleanup, err = transparentfirewall.Install(ctx, c)
				if err == nil {
					break
				}
				time.Sleep(20 * time.Millisecond)
			}
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := cleanup(); err != nil {
					t.Error(err)
				}
			})
			probe := func(forbidden bool) {
				t.Helper()
				source := "10.180.0.2"
				if strings.Contains(family.service, ":") {
					source = "fd80::2"
				}
				p := start("nca-client", "/transparentfirewall.test", "-test.run=^TestPlacementHelper$")
				p.Env = append(p.Env, "TFW_ROLE=client", "TFW_PROTOCOL=redis", "TFW_SOURCE="+source, "TFW_ADDRESS="+net.JoinHostPort(family.service, "6379"), fmt.Sprintf("TFW_FORBIDDEN=%t", forbidden))
				p.Stdout, p.Stderr = nil, nil
				out, err := p.CombinedOutput()
				if (err == nil) == forbidden || forbidden && !strings.Contains(string(out), "NOPERM blocked by gateway") {
					t.Fatalf("forbidden=%v: %v %s", forbidden, err, out)
				}
			}
			probe(false)
			before, err := os.ReadFile(log)
			if err != nil {
				t.Fatal(err)
			}
			probe(true)
			after, err := os.ReadFile(log)
			if err != nil {
				t.Fatal(err)
			}
			if string(before) != string(after) {
				t.Fatal("forbidden message reached origin")
			}
			if !strings.Contains(string(after), "peer="+family.upstreamPeer) {
				t.Fatal("upstream socket outside gateway namespace")
			}
		})
	}
}

func TestApplianceRemovalCrashLab(t *testing.T) {
	if os.Getenv("NETCAP_APPLIANCE_LAB") != "1" {
		t.Skip("disposable Docker lab only")
	}
	m := fixture(t)
	const dir = "/var/lib/nca-remove-crash"
	if _, err := Execute(context.Background(), m, dir, "apply"); err != nil {
		t.Fatal(err)
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(m)
	c := exec.Command(exe, "-test.run=^TestApplianceHelper$")
	c.Env = append(os.Environ(), "NCA_HELPER=crash-remove", "NCA_MANIFEST="+string(encoded), "NCA_STATE="+dir, "NCA_CRASH_AFTER=netns del nca-origin")
	if out, err := c.CombinedOutput(); err == nil {
		t.Fatalf("teardown writer not killed: %s", out)
	}
	if _, err := os.Lstat("/run/netns/nca-origin"); !os.IsNotExist(err) {
		t.Fatalf("teardown never reached injection point: %v", err)
	}
	if _, err := Execute(context.Background(), m, dir, "remove"); err != nil {
		t.Fatal("partial teardown retry:", err)
	}
}

func TestApplianceLinuxLab(t *testing.T) {
	if os.Getenv("NETCAP_APPLIANCE_LAB") != "1" {
		t.Skip("disposable Linux Docker lab only")
	}
	if _, e := os.Stat("/.dockerenv"); e != nil {
		t.Fatal(e)
	}
	ctx := context.Background()
	m := fixture(t)
	dir := "/var/lib/nca-test"
	before, e := command(ctx, "nft", "-j", "list", "ruleset")
	if e != nil {
		t.Fatal(e)
	}
	defer func() {
		for _, n := range m.Namespaces {
			_, _ = command(ctx, "ip", "netns", "del", n)
		}
	}()
	if _, e = Execute(ctx, m, dir, "apply"); e != nil {
		t.Fatal(e)
	}
	if _, e = Execute(ctx, m, dir, "recover"); e != nil {
		t.Fatal("idempotent recovery:", e)
	}
	if _, e = Execute(ctx, m, dir, "apply"); e != nil {
		t.Fatal("idempotent apply:", e)
	}
	wrong := m
	wrong.Nonce = "11111111111111111111111111111111"
	if _, e = Execute(ctx, wrong, dir, "recover"); e == nil {
		t.Fatal("immutable nonce changed")
	}
	checkManagement := func() {
		t.Helper()
		for _, ip := range []string{"10.181.0.3", "fd81::3"} {
			// Wait for cold neighbor discovery using unchanged bounded probes.
			var b []byte
			var err error
			for attempt := 0; attempt < 5; attempt++ {
				b, err = scoped(ctx, "nca-client", "ping", "-n", "-c", "1", "-W", "1", ip)
				if err == nil {
					break
				}
			}
			if err != nil {
				t.Fatalf("explicit management exception failed after neighbor readiness probes: %v %s", err, b)
			}
		}
	}
	checkManagement()
	checkTraffic := func(want bool) {
		t.Helper()
		for _, ip := range []string{"10.181.0.2", "fd81::2"} {
			cctx, cancel := context.WithTimeout(ctx, 3*time.Second)
			b, e := scoped(cctx, "nca-client", "ping", "-n", "-c", "1", "-W", "1", ip)
			cancel()
			if (e == nil) != want {
				t.Fatalf("traffic to %s allow=%v: %v %s", ip, want, e, b)
			}
		}
	}
	checkTraffic(false)
	start := func(verdict string) (*exec.Cmd, *os.File) {
		t.Helper()
		exe, e := os.Executable()
		if e != nil {
			t.Fatal(e)
		}
		r, w, e := os.Pipe()
		if e != nil {
			t.Fatal(e)
		}
		b, _ := json.Marshal(m)
		c := exec.Command(exe, "-test.run=^TestApplianceHelper$")
		mode := verdict
		if mode == "contender" {
			mode = "allow"
		}
		c.Env = append(os.Environ(), "NCA_HELPER="+mode, "NCA_MANIFEST="+string(b))
		c.ExtraFiles = []*os.File{w}
		c.Stdout = os.Stdout
		c.Stderr = os.Stderr
		if verdict == "contender" {
			c.Stdout = io.Discard
			c.Stderr = io.Discard
		}
		if e = c.Start(); e != nil {
			t.Fatal(e)
		}
		w.Close()
		t.Cleanup(func() { _ = c.Process.Kill(); _ = c.Wait(); _ = r.Close() })
		return c, r
	}
	ready := func(r *os.File) {
		t.Helper()
		_ = r.SetReadDeadline(time.Now().Add(5 * time.Second))
		var b [1]byte
		if _, e := io.ReadFull(r, b[:]); e != nil {
			t.Fatal("listener not ready:", e)
		}
		r.Close()
	}
	allow, r := start("allow")
	ready(r)
	checkTraffic(true)
	// A second process must fail before it can activate any packet verdict.
	contender, r := start("contender")
	_ = r.SetReadDeadline(time.Now().Add(2 * time.Second))
	var signal [1]byte
	if _, e = io.ReadFull(r, signal[:]); e == nil {
		t.Fatal("concurrent packet owner admitted")
	}
	r.Close()
	if e = contender.Wait(); e == nil {
		t.Fatal("contender unexpectedly succeeded")
	}
	if _, e = Execute(ctx, m, dir, "remove"); e == nil {
		t.Fatal("removed topology beneath live packet owner")
	}
	if _, e = Execute(ctx, m, dir, "recover"); e == nil {
		t.Fatal("reconciled topology beneath live packet owner")
	}
	_ = allow.Process.Kill()
	_ = allow.Wait()
	checkTraffic(false)
	checkManagement()
	deny, r := start("deny")
	ready(r)
	checkTraffic(false)
	// Sample continuously across SIGKILL and a new process claiming the same
	// table. Every completed protected probe must remain denied.
	done := make(chan struct{})
	results := make(chan error, 1)
	go func() {
		for i := 0; i < 6; i++ {
			for _, ip := range []string{"10.181.0.2", "fd81::2"} {
				probe, cancel := context.WithTimeout(ctx, 2*time.Second)
				_, err := scoped(probe, "nca-client", "ping", "-n", "-c", "1", "-W", "1", ip)
				cancel()
				if err == nil {
					results <- fmt.Errorf("handoff allowed %s", ip)
					return
				}
			}
		}
		close(done)
	}()
	_ = deny.Process.Kill()
	_ = deny.Wait()
	deny2, r := start("deny")
	ready(r)
	select {
	case <-done:
	case e := <-results:
		t.Fatal(e)
	case <-time.After(20 * time.Second):
		t.Fatal("handoff traffic probe timed out")
	}
	_ = deny2.Process.Kill()
	_ = deny2.Wait()
	// A foreign table blocks cleanup and survives byte-for-byte.
	if _, e = scoped(ctx, "nca-origin", "nft", "add", "table", "inet", "foreign"); e != nil {
		t.Fatal(e)
	}
	foreign, _ := scoped(ctx, "nca-origin", "nft", "list", "table", "inet", "foreign")
	if _, e = Execute(ctx, m, dir, "remove"); e == nil {
		t.Fatal("foreign table cleanup accepted")
	}
	after, _ := scoped(ctx, "nca-origin", "nft", "list", "table", "inet", "foreign")
	if string(after) != string(foreign) {
		t.Fatal("foreign table changed")
	}
	_, _ = scoped(ctx, "nca-origin", "nft", "delete", "table", "inet", "foreign")
	for _, object := range []struct{ add, del, show []string }{
		{[]string{"ip", "addr", "add", "10.181.0.99/24", "dev", "o0"}, []string{"ip", "addr", "del", "10.181.0.99/24", "dev", "o0"}, []string{"ip", "-j", "addr", "show"}},
		{[]string{"ip", "route", "add", "10.189.0.0/24", "via", "10.181.0.1"}, []string{"ip", "route", "del", "10.189.0.0/24"}, []string{"ip", "-j", "route", "show", "table", "all"}},
		{[]string{"ip", "rule", "add", "priority", "42", "table", "100"}, []string{"ip", "rule", "del", "priority", "42"}, []string{"ip", "-j", "rule", "show"}},
	} {
		if _, err := scoped(ctx, "nca-origin", object.add...); err != nil {
			t.Fatal(err)
		}
		before, err := scoped(ctx, "nca-origin", object.show...)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Execute(ctx, m, dir, "remove"); err == nil {
			t.Fatal("foreign network resource destroyed")
		}
		after, err := scoped(ctx, "nca-origin", object.show...)
		if err != nil {
			t.Fatal(err)
		}
		if string(before) != string(after) {
			t.Fatal("foreign network resource changed")
		}
		if _, err := scoped(ctx, "nca-origin", object.del...); err != nil {
			t.Fatal(err)
		}
	}
	// Drift in an owned table is also foreign state, not permission to replace it.
	_, e = scoped(ctx, "nca-gateway", "nft", "add", "chain", "inet", "netcap_networkfirewall", "foreign")
	if e != nil {
		t.Fatal(e)
	}
	if _, e = Execute(ctx, m, dir, "recover"); e == nil || !strings.Contains(e.Error(), "drift") {
		t.Fatalf("owned table drift accepted: %v", e)
	}
	_, _ = scoped(ctx, "nca-gateway", "nft", "delete", "chain", "inet", "netcap_networkfirewall", "foreign")
	if _, e = Execute(ctx, m, dir, "remove"); e != nil {
		b, _ := scoped(ctx, "nca-client", "ip", "-d", "-j", "link", "show")
		t.Log(string(b))
		t.Fatal(e)
	}
	if _, e = Execute(ctx, m, dir, "status"); e != nil {
		t.Fatal(e)
	}
	after, e = command(ctx, "nft", "-j", "list", "ruleset")
	if e != nil {
		t.Fatal(e)
	}
	if string(before) != string(after) {
		t.Fatal("default namespace rules changed")
	}
}
