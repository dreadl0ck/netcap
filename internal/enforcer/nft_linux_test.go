//go:build linux

package enforcer

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func testNFT(t *testing.T) *NFTBackend {
	t.Helper()
	c := testConfig()
	c.DryRun = false
	c.Namespace = "lab"
	c, _, err := normalize(c)
	if err != nil {
		t.Fatal(err)
	}
	return &NFTBackend{config: c}
}
func testLease(b *NFTBackend) Lease {
	return Lease{ID: "incident", Source: "198.51.100.1", Scope: b.config.Scope, TTLSeconds: 60, ExpiresAt: time.Now().UTC().Add(time.Minute)}
}
func nftFixture(t *testing.T, b *NFTBackend, l Lease, owner string) []byte {
	t.Helper()
	data, err := json.Marshal(map[string]any{"nftables": []any{
		map[string]any{"table": map[string]any{"family": "inet", "name": b.config.Table, "comment": owner}},
		map[string]any{"chain": map[string]any{"name": "leases", "type": "filter", "hook": b.config.Scope.Hook, "prio": 0, "policy": "accept"}},
		map[string]any{"set": map[string]any{"name": setName(l.ID), "comment": metadata(l)}},
		map[string]any{"rule": map[string]any{"comment": "netcap-lease:" + l.ID, "handle": uint64(42)}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestNFTScriptScopeAndDeadline(t *testing.T) {
	b := testNFT(t)
	l := testLease(b)
	now := l.ExpiresAt.Add(-3 * time.Second)
	script, err := b.applyScript(l, now)
	if err != nil {
		t.Fatal(err)
	}
	for _, part := range []string{"type ipv4_addr; flags timeout; timeout 3000ms", `iifname "veth0" ip daddr 10.44.0.1/32 ip saddr @`, "tcp dport 443 counter drop", "198.51.100.1 timeout 3000ms"} {
		if !strings.Contains(script, part) {
			t.Errorf("missing %s in %s", part, script)
		}
	}
	if strings.Contains(script, "flush") || strings.Contains(script, "output") {
		t.Fatal(script)
	}
	if s, err := b.applyScript(l, l.ExpiresAt); err != nil || s != "" {
		t.Fatal("expired action emitted", s, err)
	}
	if len(metadata(l)) > 128 {
		t.Fatal("nft comment too long")
	}
	b.config.Scope.DestinationCIDR = "2001:db8:1::1/128"
	b.config.Scope.Hook = "forward"
	b.config.Scope.Protocol = "udp"
	l.Scope = b.config.Scope
	l.Source = "2001:db8:2::1"
	script, err = b.applyScript(l, now)
	if err != nil || !strings.Contains(script, "type ipv6_addr") || !strings.Contains(script, "ip6 daddr") || !strings.Contains(script, "udp dport") {
		t.Fatal(script, err)
	}
}

func TestNFTCollisionFailureAndExactDelete(t *testing.T) {
	b := testNFT(t)
	l := testLease(b)
	fixture := nftFixture(t, b, l, b.owner())
	calls := 0
	b.run = func(_ context.Context, args []string, script string) ([]byte, error) {
		calls++
		if strings.Join(args, " ") == "-j list tables" {
			return []byte(`{"nftables":[{"table":{"family":"inet","name":"` + b.config.Table + `"}}]}`), nil
		}
		if strings.Join(args, " ") == "-j list table inet "+b.config.Table {
			return fixture, nil
		}
		if strings.Join(args, " ") != "-f -" || script != "delete rule inet "+b.config.Table+" leases handle 42\ndelete set inet "+b.config.Table+" "+setName(l.ID)+"\n" {
			t.Fatalf("unexpected executor call %v %s", args, script)
		}
		return nil, nil
	}
	if err := b.Apply(context.Background(), l); err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Fatal("idempotency wrote nft", calls)
	}
	wrong := l
	wrong.Source = "198.51.100.2"
	if err := b.Delete(context.Background(), wrong); !errors.Is(err, ErrConflict) {
		t.Fatal(err)
	}
	if err := b.Delete(context.Background(), l); err != nil {
		t.Fatal(err)
	}
	fixture = nftFixture(t, b, l, "someone-else")
	if _, err := b.List(context.Background()); err == nil {
		t.Fatal("adopted unowned table")
	}
	calls = 0
	b.run = func(_ context.Context, _ []string, script string) ([]byte, error) {
		calls++
		if script != "" {
			t.Fatal("write after list failure")
		}
		return nil, errors.New("permission denied")
	}
	if _, err := b.List(context.Background()); err == nil || calls != 1 {
		t.Fatal("list failure treated as absence")
	}
}

func TestNFTRequiresExplicitNamespace(t *testing.T) {
	c := testConfig()
	c.DryRun = false
	if _, err := NewNFTBackend(c); err == nil {
		t.Fatal("default namespace accepted")
	}
}
