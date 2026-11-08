package firewall

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/dreadl0ck/netcap/internal/firewallauth"
)

func TestIdentityBootstrapStrictOriginsAndGrants(t *testing.T) {
	t.Setenv("TEST_AUTH_TOKEN", "synthetic-bootstrap-token-32-bytes")
	scope := firewallauth.Scope{Tenant: "lab", App: "web", Environment: "test", Target: "edge"}
	p := firewallauth.Principal{ID: "reader", Grants: []firewallauth.Grant{{Scope: scope, Actions: []firewallauth.Action{firewallauth.Read}}}}
	for _, tc := range []struct {
		name, origin string
		principal    firewallauth.Principal
		extra        bool
		valid        bool
	}{
		{"exact", "https://console.example", p, false, true},
		{"wildcard", "https://*.example", p, false, false},
		{"path", "https://console.example/path", p, false, false},
		{"userinfo", "https://user@console.example", p, false, false},
		{"null", "null", p, false, false},
		{"invalid-grants", "", firewallauth.Principal{ID: "reader", Grants: []firewallauth.Grant{{Scope: scope, Actions: []firewallauth.Action{"administrator"}}}}, false, false},
		{"unknown-field", "", p, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "auth.json")
			cfg := map[string]any{"stateDir": filepath.Join(dir, "identity"), "scope": scope, "origin": tc.origin, "static": []any{map[string]any{"tokenEnv": "TEST_AUTH_TOKEN", "principal": tc.principal}}, "stdio": tc.principal}
			if tc.extra {
				cfg["adminApproved"] = true
			}
			raw, _ := json.Marshal(cfg)
			if err := os.WriteFile(path, raw, 0600); err != nil {
				t.Fatal(err)
			}
			a, _, err := loadAuth(path)
			if a != nil {
				defer a.Close()
			}
			if (err == nil) != tc.valid {
				t.Fatalf("bootstrap valid=%v: %v", tc.valid, err)
			}
			if tc.valid {
				identity, err := a.Authenticate(context.Background(), os.Getenv("TEST_AUTH_TOKEN"))
				if err != nil || !identity.Allows(firewallauth.Read, scope) || identity.Allows(firewallauth.Deploy, scope) {
					t.Fatal("bootstrap grants", err)
				}
			}
		})
	}
}
