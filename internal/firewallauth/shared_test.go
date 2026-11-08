package firewallauth_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/internal/firewallauth"
	"github.com/dreadl0ck/netcap/internal/firewallfleet"
	"github.com/dreadl0ck/netcap/internal/firewallstate"
	"github.com/dreadl0ck/netcap/internal/policy"
	"github.com/dreadl0ck/netcap/internal/policystate"
	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

type sharedInput struct {
	URL, Namespace, Key, Token, Receipt, Mode, Digest string
	Provider                                          firewallauth.Provider
}

func openSharedTest(t *testing.T, in sharedInput) (*firewallauth.Authority, *firewallauth.Approvals) {
	t.Helper()
	db, err := firewallstate.OpenPostgres(context.Background(), in.URL, in.Namespace)
	if err != nil {
		t.Fatal(err)
	}
	key, err := base64.StdEncoding.DecodeString(in.Key)
	if err != nil {
		t.Fatal(err)
	}
	a, p, err := firewallauth.OpenShared(context.Background(), firewallauth.Config{Providers: []firewallauth.Provider{in.Provider}}, db, key, []firewallauth.Protected{{Action: firewallauth.Deploy, Scope: scope}})
	if err != nil {
		db.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { a.Close() })
	return a, p
}
func TestSharedAuthProcessHelper(t *testing.T) {
	if os.Getenv("NETCAP_SHARED_AUTH_HELPER") != "1" {
		return
	}
	var in sharedInput
	if err := json.NewDecoder(os.Stdin).Decode(&in); err != nil {
		t.Fatal(err)
	}
	a, p := openSharedTest(t, in)
	identity, err := a.Authenticate(context.Background(), in.Token)
	if err == nil {
		ctx := firewallauth.WithPrincipal(context.Background(), identity)
		switch in.Mode {
		case "consume":
			err = p.Check(ctx, firewallauth.Deploy, scope, in.Digest, in.Receipt)
		case "revoke":
			err = a.Revoke(ctx, in.Digest)
		case "foreign":
			if identity.Allows(firewallauth.Deploy, firewallauth.Scope{Tenant: "two", App: scope.App, Environment: scope.Environment}) {
				t.Fatal("cross-tenant grant")
			}
		}
	}
	fmt.Printf("SHARED_AUTH_ALLOWED=%t\n", err == nil)
}
func sharedChild(t *testing.T, in sharedInput) bool {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	c := exec.Command(exe, "-test.run=^TestSharedAuthProcessHelper$", "-test.v")
	c.Env = append(os.Environ(), "NETCAP_SHARED_AUTH_HELPER=1")
	b, _ := json.Marshal(in)
	c.Stdin = strings.NewReader(string(b))
	out, err := c.CombinedOutput()
	if err != nil {
		t.Errorf("child: %v %s", err, out)
		return false
	}
	return strings.Contains(string(out), "SHARED_AUTH_ALLOWED=true")
}
func TestSharedPostgresIdentityProcesses(t *testing.T) {
	raw := os.Getenv("NETCAP_POSTGRES_TEST_URL")
	if raw == "" {
		t.Skip("NETCAP_POSTGRES_TEST_URL required")
	}
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	_, approvalKey, _ := ed25519.GenerateKey(rand.Reader)
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: pub, KeyID: "test", Algorithm: "EdDSA", Use: "sig"}}})
	}))
	defer provider.Close()
	actor := firewallauth.Principal{ID: "actor", Grants: []firewallauth.Grant{{Scope: scope, Actions: []firewallauth.Action{firewallauth.Read, firewallauth.Author, firewallauth.Evaluate, firewallauth.Deploy}}}}
	approver := firewallauth.Principal{ID: "approver", Grants: []firewallauth.Grant{{Scope: scope, Actions: []firewallauth.Action{firewallauth.Approve, firewallauth.Deploy}}}}
	admin := firewallauth.Principal{ID: "credential-admin", Grants: []firewallauth.Grant{{Actions: []firewallauth.Action{firewallauth.ManageCredentials}}}}
	in := sharedInput{URL: raw, Namespace: fmt.Sprintf("ncf_auth_%d_%x", os.Getpid(), time.Now().UnixNano()), Key: base64.StdEncoding.EncodeToString(approvalKey), Provider: firewallauth.Provider{Issuer: "test-issuer", Audience: "firewall", JWKSURL: provider.URL, Subjects: map[string]firewallauth.Principal{"actor": actor, "approver": approver, "admin": admin}}}
	db, err := firewallstate.OpenPostgres(context.Background(), raw, in.Namespace)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	defer func() {
		_, err := db.DB.Exec(`DROP SCHEMA "` + in.Namespace + `" CASCADE`)
		if err != nil {
			t.Error(err)
		}
	}()
	a, p := openSharedTest(t, in)
	token := func(sub string) string {
		signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: key}, (&jose.SignerOptions{}).WithHeader("kid", "test"))
		if err != nil {
			t.Fatal(err)
		}
		now := time.Now()
		s, err := jwt.Signed(signer).Claims(jwt.Claims{Issuer: in.Provider.Issuer, Subject: sub, Audience: jwt.Audience{"firewall"}, IssuedAt: jwt.NewNumericDate(now), Expiry: jwt.NewNumericDate(now.Add(2 * time.Minute))}).Serialize()
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	in.Token = token("actor")
	if _, err = a.Authenticate(context.Background(), in.Token); err != nil {
		t.Fatal(err)
	}
	in.Mode = "foreign"
	if !sharedChild(t, in) {
		t.Fatal("fake-provider authentication on independent process failed")
	}
	// Independent service pools share both the identity ledger and service state.
	a2, _ := openSharedTest(t, in)
	resource := firewallstate.Scope{Tenant: scope.Tenant, App: scope.App}
	ctx := firewallauth.WithPrincipal(context.Background(), actor)
	bundle := `{"version":"1","id":"shared-auth","mode":"enforce","default":"allow","rules":[]}`
	parsed, err := policy.Parse([]byte(bundle))
	if err != nil {
		t.Fatal(err)
	}
	compiled, err := policy.Compile(parsed)
	if err != nil {
		t.Fatal(err)
	}
	var firstStage string
	for i, auth := range []*firewallauth.Authority{a, a2} {
		fleet, err := firewallfleet.New(firewallfleet.Config{DatabaseURL: raw, DatabaseNamespace: in.Namespace + "_f", Auth: auth, Environment: scope.Environment})
		if err != nil {
			t.Fatal(err)
		}
		defer fleet.Close()
		out, err := fleet.Execute(context.Background(), in.Token, "stage", firewallfleet.Request{Scope: resource, Bundle: bundle})
		if err != nil {
			t.Fatal(err)
		}
		encoded, _ := json.Marshal(out)
		if i == 0 {
			firstStage = string(encoded)
		} else if firstStage != string(encoded) {
			t.Fatal("fleet artifact differs across owners")
		}
		counter, err := firewallstate.New(firewallstate.Config{DatabaseURL: raw, DatabaseNamespace: in.Namespace + "_c", Auth: auth, Environment: scope.Environment})
		if err != nil {
			t.Fatal(err)
		}
		defer counter.Close()
		result, err := counter.Bind(resource).Count(ctx, firewallstate.Key{Revision: compiled.Revision(), Group: firewallstate.Digest("shared")}, firewallstate.Window{Mode: "fixed", Duration: time.Minute}, time.Now())
		if err != nil || result.Count != int64(i+1) {
			t.Fatalf("shared counter: %+v %v", result, err)
		}
		if _, err := counter.Bind(firewallstate.Scope{Tenant: "two", App: scope.App}).Count(ctx, firewallstate.Key{Revision: compiled.Revision(), Group: firewallstate.Digest("shared")}, firewallstate.Window{Mode: "fixed", Duration: time.Minute}, time.Now()); err == nil {
			t.Fatal("counter crossed tenant")
		}
		native, err := policystate.New(policystate.Config{DatabaseURL: raw, DatabaseNamespace: in.Namespace + "_n", Auth: auth, Environment: scope.Environment})
		if err != nil {
			t.Fatal(err)
		}
		defer native.Close()
		decision, err := native.Evaluate(ctx, resource, policystate.Request{Revision: compiled.Revision(), Bundle: json.RawMessage(bundle), Event: &policy.Event{Protocol: "http", Phase: "request"}})
		if err != nil || decision.Verdict != "allow" {
			t.Fatalf("native owner: %+v %v", decision, err)
		}
	}
	defer func() {
		for _, suffix := range []string{"_f", "_c", "_n"} {
			if _, err := db.DB.Exec(`DROP SCHEMA "` + in.Namespace + suffix + `" CASCADE`); err != nil {
				t.Error(err)
			}
		}
	}()
	in.Digest = firewallauth.Digest("exact deployment")
	in.Receipt, err = p.Issue(firewallauth.WithPrincipal(context.Background(), approver), firewallauth.ApprovalRequest{Actor: actor.ID, Action: firewallauth.Deploy, Scope: scope, Digest: in.Digest})
	if err != nil {
		t.Fatal(err)
	}
	in.Mode = "consume"
	var wg sync.WaitGroup
	results := make(chan bool, 2)
	for range 2 {
		wg.Go(func() { results <- sharedChild(t, in) })
	}
	wg.Wait()
	close(results)
	allowed := 0
	for ok := range results {
		if ok {
			allowed++
		}
	}
	if allowed != 1 {
		t.Fatalf("global one-use receipt accepted by %d processes", allowed)
	}
	// A distinct tenant cannot spend a receipt even with the same actor identity.
	foreign := actor
	foreign.Grants = []firewallauth.Grant{{Scope: firewallauth.Scope{Tenant: "two", App: "web", Environment: "prod"}, Actions: []firewallauth.Action{firewallauth.Deploy}}}
	if foreign.Allows(firewallauth.Deploy, scope) {
		t.Fatal("cross tenant")
	}
	actorToken := in.Token
	in.Token, in.Mode, in.Digest = token("admin"), "revoke", firewallstate.Digest(actorToken)
	if !sharedChild(t, in) {
		t.Fatal("cross-process revoke failed")
	}
	if _, err = a.Authenticate(context.Background(), actorToken); err == nil {
		t.Fatal("revocation not visible to existing owner")
	}
	in.Token, in.Mode = actorToken, "foreign"
	if sharedChild(t, in) {
		t.Fatal("revoked JWT accepted after process restart")
	}
	// Set ordering and explicit default values have the same policy fingerprint.
	in.Provider.TTL = time.Minute
	in.Provider.RevokedIDs = []string{}
	normalizedActor := actor
	normalizedActor.Grants = []firewallauth.Grant{{Scope: scope, Actions: []firewallauth.Action{firewallauth.Deploy, firewallauth.Evaluate, firewallauth.Author, firewallauth.Read, firewallauth.Read}}}
	in.Provider.Subjects["actor"] = normalizedActor
	openSharedTest(t, in)
	in.Provider.Subjects["actor"] = foreign
	otherDB, err := firewallstate.OpenPostgres(context.Background(), raw, in.Namespace)
	if err != nil {
		t.Fatal(err)
	}
	defer otherDB.Close()
	if other, _, err := firewallauth.OpenShared(context.Background(), firewallauth.Config{Providers: []firewallauth.Provider{in.Provider}}, otherDB, approvalKey, []firewallauth.Protected{{Action: firewallauth.Deploy, Scope: scope}}); err == nil {
		other.Close()
		t.Fatal("changed tenant policy joined ledger")
	}
}
