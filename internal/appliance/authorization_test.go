package appliance

import (
	"context"
	"testing"

	"github.com/dreadl0ck/netcap/internal/firewallauth"
)

func TestProductionPlanRequiresBoundOperatorAndReview(t *testing.T) {
	m := fixture(t)
	m.Mode, m.TargetID = "production", "edge-a"
	p, err := m.Plan()
	if err != nil {
		t.Fatal(err)
	}
	scope := firewallauth.Scope{Tenant: "one", App: "network", Environment: "production", Target: "edge-a"}
	principal := firewallauth.Principal{ID: "operator", Grants: []firewallauth.Grant{{Scope: scope, Actions: []firewallauth.Action{firewallauth.Deploy}}}}
	ctx := firewallauth.WithPrincipal(context.Background(), principal)
	if AuthorizeProduction(ctx, m) == nil {
		t.Fatal("missing review admitted")
	}
	for _, b := range []Bootstrap{{Scope: scope, ReviewedDigest: "wrong"}, {Scope: firewallauth.Scope{Tenant: "two", App: scope.App, Environment: scope.Environment, Target: scope.Target}, ReviewedDigest: p.Digest}, {Scope: firewallauth.Scope{Tenant: scope.Tenant, App: scope.App, Environment: scope.Environment, Target: "edge-b"}, ReviewedDigest: p.Digest}} {
		if AuthorizeProduction(WithBootstrap(ctx, b), m) == nil {
			t.Fatal("foreign target/grant or unreviewed manifest admitted")
		}
	}
	approved := WithBootstrap(ctx, Bootstrap{Scope: scope, ReviewedDigest: p.Digest})
	if err := AuthorizeProduction(approved, m); err != nil {
		t.Fatal(err)
	}
	m.Nonce = "11111111111111111111111111111111"
	if AuthorizeProduction(approved, m) == nil {
		t.Fatal("review substituted topology nonce")
	}
}
