package firewall_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/dreadl0ck/netcap/internal/waf"
)

func TestRouteRuntimeValidationAndRelativeCapabilities(t *testing.T) {
	t.Setenv("NETCAP_FIREWALL_ADMIN_TOKEN", "")
	dir := t.TempDir()
	write := func(name string, b []byte) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), b, 0600); err != nil {
			t.Fatal(err)
		}
	}
	write("default.yaml", []byte("version: netcap-policy/v1\nid: default\nmode: enforce\ndefault: allow\nrules: []\n"))
	write("a.yaml", []byte("version: netcap-policy/v1\nid: a\nmode: enforce\ndefault: allow\nrules: []\n"))
	cfg := waf.Config{Version: "netcap-firewall/v1", Listen: "127.0.0.1:0", AdminListen: "127.0.0.1:0", PolicyFile: "default.yaml", MaxConcurrent: 8, BodyTimeout: "1s", Routes: []waf.RouteConfig{{ID: "a", PolicyID: "a", PolicyFile: "a.yaml", Hosts: []string{"a.example"}, Methods: []string{"GET"}, PathPrefix: "/", Upstream: "http://127.0.0.1:1", MaxBodyBytes: 1024, MaxResponseBytes: 1024, MaxConcurrent: 4}}}
	b, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	write("runtime.json", b)
	args := []string{"validate", "--config", filepath.Join(dir, "runtime.json")}
	if out, err := runRoot(t.Context(), args...); err != nil {
		t.Fatalf("validate routes: %v %s", err, out)
	}
	if _, err := runRoot(t.Context(), append(args, "--managed")...); err == nil {
		t.Fatal("global managed target accepted for routes")
	}
	for _, extra := range [][]string{{"--managed", "--route-id", "a"}, {"--websocket"}} {
		if out, err := runRoot(t.Context(), append(args, extra...)...); err != nil {
			t.Fatalf("composed route runtime %v: %v %s", extra, err, out)
		}
	}
	if _, err := runRoot(t.Context(), append(args, "--managed", "--route-id", "unknown")...); err == nil {
		t.Fatal("unknown route management scope accepted")
	}
	write("a.yaml", []byte("version: [invalid"))
	if _, err := runRoot(t.Context(), args...); err == nil {
		t.Fatal("invalid sibling policy passed runtime validation")
	}
}
