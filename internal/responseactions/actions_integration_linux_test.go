//go:build linux && integration

package responseactions

import (
	"context"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/internal/enforcer"
	"github.com/dreadl0ck/netcap/internal/policy"
)

func TestTypedBrokerRealKernel(t *testing.T) {
	if os.Getenv("ENFORCER_NETNS_TEST") != "1" {
		t.Skip("requires disposable privileged Docker lab")
	}
	if _, err := os.Stat("/.dockerenv"); err != nil {
		t.Fatal("Docker-only qualification")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	run := func(args ...string) {
		t.Helper()
		out, err := exec.CommandContext(ctx, "ip", args...).CombinedOutput()
		if err != nil {
			t.Fatalf("ip %v: %v %s", args, err, out)
		}
	}
	ns := "nca_broker"
	run("netns", "add", ns)
	t.Cleanup(func() { _ = exec.Command("ip", "netns", "del", ns).Run() })
	run("-n", ns, "link", "add", "eth0", "type", "dummy")
	run("-n", ns, "link", "set", "eth0", "up")
	profiles := map[string]enforcer.Profile{
		"isolate": {Kind: enforcer.Quarantine, Services: []enforcer.Service{{Protocol: "tcp", Port: 444}}},
		"packets": {Kind: enforcer.RateSource, Services: []enforcer.Service{{Protocol: "udp", Port: 53}}, Unit: "packets", Rate: 10, Burst: 3},
		"bytes":   {Kind: enforcer.RateSource, Services: []enforcer.Service{{Protocol: "udp", Port: 54}}, Unit: "bytes", Rate: 1000, Burst: 2000},
	}
	c, err := enforcer.New(enforcer.Config{Token: strings.Repeat("t", 32), Namespace: ns, Table: "netcap_firewall_broker", Scope: testScope, Profiles: profiles}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	server := httptest.NewTLSServer(c.Handler())
	defer server.Close()
	cfg := configFor(t, server)
	scope := cfg.Scopes["edge"]
	scope.Profiles = profiles
	cfg.Scopes["edge"] = scope
	b := newBroker(t, cfg)
	for _, action := range []struct{ kind, profile string }{
		{"block_source", ""}, {"quarantine", "isolate"}, {"rate_source", "packets"}, {"rate_source", "bytes"}, {"drop_flow", ""}, {"reject_flow", ""},
	} {
		i := typedIntent(action.kind, action.profile)
		var flow *enforcer.Flow
		if strings.HasSuffix(action.kind, "_flow") {
			i.Target = "source"
			i.Flow = enforcer.Flow{Destination: "198.51.100.1", Protocol: "tcp", SourcePort: 12345, DestinationPort: 443}
			flow = &i.Flow
		}
		i.ID = policy.IntentID(i)
		if r := b.SubmitFlow(i, i.Source, flow); r.Status != "requested" {
			t.Fatal(r)
		}
		await(t, b, i.ID, "applied")
		ls, err := c.List(ctx)
		if err != nil || len(ls) != 1 || ls[0].Action != intentAction(i) || !ls[0].ExpiresAt.Equal(i.ExpiresAt) {
			t.Fatalf("kernel delivery: %+v %v", ls, err)
		}
		if err = c.Delete(ctx, i.ID); err != nil {
			t.Fatal(err)
		}
	}
	// Redirect uses its own immutable NAT grant and real kernel backend.
	network := testScope
	network.Hook = "prerouting"
	routes := map[string]enforcer.Profile{"operator": {Kind: enforcer.RedirectSource, Services: []enforcer.Service{{Protocol: "tcp", Port: 443}}, Destination: "198.51.100.2", Port: 8443}}
	nat, err := enforcer.New(enforcer.Config{Token: strings.Repeat("t", 32), Namespace: ns, Table: "netcap_firewall_broker_nat", Scope: network, Profiles: routes}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer nat.Close()
	natServer := httptest.NewTLSServer(nat.Handler())
	defer natServer.Close()
	cfg = configFor(t, natServer)
	scope = cfg.Scopes["edge"]
	scope.Network = network
	scope.Profiles = routes
	cfg.Scopes["edge"] = scope
	routeBroker := newBroker(t, cfg)
	i := typedIntent("redirect_source", "operator")
	routeBroker.Submit(i, i.Source)
	await(t, routeBroker, i.ID, "applied")
	if err = nat.Delete(ctx, i.ID); err != nil {
		t.Fatal(err)
	}
	t.Log("authenticated MCP capabilities/schema -> broker -> REST -> real nft: all six packet actions, packet/byte profiles, exact deadlines")
}
