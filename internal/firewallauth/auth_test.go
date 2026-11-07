package firewallauth

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	_ "modernc.org/sqlite"
)

func TestGrantDimensionsAndNoAmbientPrivilege(t *testing.T) {
	s := Scope{Tenant: "one", App: "web", Environment: "prod", Target: "edge"}
	p := Principal{ID: "agent", Grants: []Grant{{s, []Action{Read, Evaluate}}}}
	for _, a := range []Action{Author, Deploy, Rollback, Lease, Audit, Approve, ""} {
		if p.Allows(a, s) {
			t.Fatalf("unexpected action %s", a)
		}
	}
	for _, field := range []string{"tenant", "app", "environment", "target"} {
		other := s
		switch field {
		case "tenant":
			other.Tenant = "two"
		case "app":
			other.App = "other"
		case "environment":
			other.Environment = "dev"
		case "target":
			other.Target = "other"
		}
		if p.Allows(Read, other) {
			t.Fatalf("scope escape %s", field)
		}
	}
	if Require(context.Background(), Read, s) == nil {
		t.Fatal("ambient privilege")
	}
	a, err := New(Config{Static: []Static{{strings.Repeat("s", 32), Principal{ID: "empty"}}}})
	if err != nil {
		t.Fatal(err)
	}
	empty, err := a.Authenticate(context.Background(), strings.Repeat("s", 32))
	if err != nil || empty.Allows(Read, Scope{}) {
		t.Fatal("empty grants must deny")
	}
	if err = a.Reload(Config{}); err != nil {
		t.Fatal(err)
	}
	if _, err = a.Authenticate(context.Background(), strings.Repeat("s", 32)); err == nil {
		t.Fatal("removed static credential accepted")
	}
}

func signToken(t *testing.T, key ed25519.PrivateKey, kid string, c jwt.Claims) string {
	t.Helper()
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: key}, (&jose.SignerOptions{}).WithHeader("kid", kid))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := jwt.Signed(signer).Claims(c).Serialize()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
func TestOIDCVerificationRotationRevocationAndFetchBudget(t *testing.T) {
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	pub2, key2, _ := ed25519.GenerateKey(rand.Reader)
	var mu sync.Mutex
	keys := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: pub, KeyID: "one", Algorithm: "EdDSA", Use: "sig"}}}
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		mu.Lock()
		defer mu.Unlock()
		_ = json.NewEncoder(w).Encode(keys)
	}))
	defer srv.Close()
	provider := Provider{Issuer: srv.URL, Audience: "firewall", JWKSURL: srv.URL + "/keys", TTL: time.Second, Subjects: map[string]Principal{"workload": {ID: "worker", Grants: []Grant{{Scope{Tenant: "one", App: "web"}, []Action{Read}}}}}}
	a, err := New(Config{Providers: []Provider{provider}})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	claims := jwt.Claims{Issuer: srv.URL, Subject: "workload", Audience: jwt.Audience{"firewall"}, IssuedAt: jwt.NewNumericDate(now), Expiry: jwt.NewNumericDate(now.Add(5 * time.Minute)), ID: "session-one"}
	valid := signToken(t, key, "one", claims)
	if _, err = a.Authenticate(context.Background(), valid); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*jwt.Claims){"issuer": func(c *jwt.Claims) { c.Issuer = "evil" }, "audience": func(c *jwt.Claims) { c.Audience = jwt.Audience{"other"} }, "expired": func(c *jwt.Claims) { c.Expiry = jwt.NewNumericDate(now.Add(-time.Minute)) }, "future": func(c *jwt.Claims) { c.IssuedAt = jwt.NewNumericDate(now.Add(time.Minute)) }, "no-expiry": func(c *jwt.Claims) { c.Expiry = nil }, "long-lived": func(c *jwt.Claims) { c.Expiry = jwt.NewNumericDate(now.Add(24 * time.Hour)) }, "foreign-subject": func(c *jwt.Claims) { c.Subject = "unbound" }} {
		t.Run(name, func(t *testing.T) {
			c := claims
			change(&c)
			if _, err := a.Authenticate(context.Background(), signToken(t, key, "one", c)); err == nil {
				t.Fatal("invalid JWT accepted")
			}
		})
	}
	for i := 0; i < 100; i++ {
		if _, err = a.Authenticate(context.Background(), signToken(t, key, "unknown", claims)); err == nil {
			t.Fatal("unknown kid accepted")
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("unbounded unknown-kid fetching: %d", calls.Load())
	}
	mu.Lock()
	keys.Keys = []jose.JSONWebKey{{Key: pub2, KeyID: "two", Algorithm: "EdDSA", Use: "sig"}}
	mu.Unlock()
	time.Sleep(1100 * time.Millisecond)
	if _, err = a.Authenticate(context.Background(), signToken(t, key2, "two", claims)); err != nil {
		t.Fatalf("rotated key: %v", err)
	}
	if _, err = a.Authenticate(context.Background(), valid); err == nil {
		t.Fatal("removed key accepted")
	}
	provider.RevokedIDs = []string{"session-one"}
	if err = a.Reload(Config{Providers: []Provider{provider}}); err != nil {
		t.Fatal(err)
	}
	if _, err = a.Authenticate(context.Background(), signToken(t, key2, "two", claims)); err == nil {
		t.Fatal("revoked JWT accepted")
	}
	provider.JWKSURL = "http://169.254.169.254/latest"
	if _, err = New(Config{Providers: []Provider{provider}}); err == nil {
		t.Fatal("cleartext remote JWKS accepted")
	}
	if _, err = a.Authenticate(context.Background(), `eyJhbGciOiJub25lIn0.e30.`); err == nil {
		t.Fatal("unsigned JWT accepted")
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.HS256, Key: []byte(strings.Repeat("h", 32))}, (&jose.SignerOptions{}).WithHeader("kid", "two"))
	if err != nil {
		t.Fatal(err)
	}
	hmacToken, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = a.Authenticate(context.Background(), hmacToken); err == nil {
		t.Fatal("symmetric algorithm accepted")
	}
	if _, err = a.Authenticate(context.Background(), signToken(t, key2, strings.Repeat("k", 129), claims)); err == nil {
		t.Fatal("oversized kid accepted")
	}
}

func TestOIDCNeverFollowsTokenKeyURLsOrRedirects(t *testing.T) {
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	var hits atomic.Int32
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1); t.Error("untrusted key URL fetched") }))
	defer evil.Close()
	var redirect atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if redirect.Load() {
			http.Redirect(w, r, evil.URL, 302)
			return
		}
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: pub, KeyID: "trusted", Algorithm: "EdDSA", Use: "sig"}}})
	}))
	defer srv.Close()
	cfg := Config{Providers: []Provider{{Issuer: srv.URL, Audience: "firewall", JWKSURL: srv.URL + "/keys", Subjects: map[string]Principal{"worker": {ID: "worker"}}}}}
	a, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	claims := jwt.Claims{Issuer: srv.URL, Audience: jwt.Audience{"firewall"}, Subject: "worker", IssuedAt: jwt.NewNumericDate(now), Expiry: jwt.NewNumericDate(now.Add(time.Minute))}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: key}, (&jose.SignerOptions{}).WithHeader("kid", "trusted").WithHeader("jku", evil.URL).WithHeader("x5u", evil.URL))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = a.Authenticate(context.Background(), raw); err != nil {
		t.Fatal("trusted signature", err)
	}
	redirect.Store(true)
	if err = a.Reload(cfg); err != nil {
		t.Fatal(err)
	}
	if _, err = a.Authenticate(context.Background(), raw); err == nil {
		t.Fatal("redirect key accepted")
	}
	if hits.Load() != 0 {
		t.Fatal("untrusted endpoint contacted")
	}
}

func TestApprovalSeparatePrincipalDigestCASAndDurableReplay(t *testing.T) {
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	path := filepath.Join(t.TempDir(), "receipts.sqlite")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	store, err := NewSQLReplayStore(context.Background(), db)
	if err != nil {
		t.Fatal(err)
	}
	scope := Scope{Tenant: "one", App: "web", Environment: "prod", Target: "edge"}
	a, err := NewApprovals(key, store, []Protected{{Deploy, scope}})
	if err != nil {
		t.Fatal(err)
	}
	actor := Principal{ID: "agent", Grants: []Grant{{scope, []Action{Deploy}}}}
	approver := Principal{ID: "operator", Grants: []Grant{{scope, []Action{Approve, Deploy}}}}
	r := ApprovalRequest{Actor: actor.ID, Action: Deploy, Scope: scope, Digest: Digest(map[string]any{"revision": "new", "expected_revision": "old", "generation": 3})}
	if _, err = a.Issue(WithPrincipal(context.Background(), actor), r); err == nil {
		t.Fatal("self approval accepted")
	}
	receipt, err := a.Issue(WithPrincipal(context.Background(), approver), r)
	if err != nil {
		t.Fatal(err)
	}
	ctx := WithPrincipal(context.Background(), actor)
	if a.Check(ctx, Deploy, scope, Digest("changed CAS"), receipt) == nil {
		t.Fatal("changed CAS digest accepted")
	}
	if a.Check(ctx, Deploy, scope, r.Digest, receipt+"x") == nil {
		t.Fatal("tampered signature accepted")
	}
	if err = a.Check(ctx, Deploy, scope, r.Digest, receipt); err != nil {
		t.Fatal(err)
	}
	if err = db.Close(); err != nil {
		t.Fatal(err)
	}
	db, err = sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	store, err = NewSQLReplayStore(context.Background(), db)
	if err != nil {
		t.Fatal(err)
	}
	a, _ = NewApprovals(key, store, []Protected{{Deploy, scope}})
	if a.Check(ctx, Deploy, scope, r.Digest, receipt) == nil {
		t.Fatal("replay survived restart")
	}
	other := scope
	other.Environment = "dev"
	if err = a.Check(ctx, Deploy, other, r.Digest, ""); err != nil {
		t.Fatal("ordinary delegated change incorrectly requires approval")
	}
}

func TestDurableRevocationAndStaticRotation(t *testing.T) {
	ctx := context.Background()
	old, fresh, admin := strings.Repeat("o", 32), strings.Repeat("n", 32), strings.Repeat("a", 32)
	worker := Principal{ID: "worker", Grants: []Grant{{Scope{Tenant: "one", App: "web"}, []Action{Read}}}}
	operator := Principal{ID: "operator", Grants: []Grant{{Scope{}, []Action{ManageCredentials}}}}
	cfg := Config{Static: []Static{{old, worker}, {admin, operator}}}
	dir := filepath.Join(t.TempDir(), "identity")
	a, _, err := OpenPersistent(cfg, dir, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(old))
	fingerprint := hex.EncodeToString(sum[:])
	if a.Revoke(WithPrincipal(ctx, worker), fingerprint) == nil {
		t.Fatal("reader revoked credential")
	}
	if err = a.Revoke(WithPrincipal(ctx, operator), strings.ToUpper(fingerprint)); err != nil {
		t.Fatal(err)
	}
	if _, err = a.Authenticate(ctx, old); err == nil {
		t.Fatal("revoked credential accepted")
	}
	if err = a.Close(); err != nil {
		t.Fatal(err)
	}
	a, _, err = OpenPersistent(cfg, dir, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	if _, err = a.Authenticate(ctx, old); err == nil {
		t.Fatal("revocation lost after restart")
	}
	cfg.Static = []Static{{fresh, worker}, {admin, operator}}
	if err = a.Reload(cfg); err != nil {
		t.Fatal(err)
	}
	if _, err = a.Authenticate(ctx, fresh); err != nil {
		t.Fatal("rotated credential rejected", err)
	}
	if _, err = a.Authenticate(ctx, old); err == nil {
		t.Fatal("rotation re-admitted revoked credential")
	}
	// Neither query credentials nor a browser origin can bypass lifecycle auth.
	h := a.LifecycleHandler("https://console.example")
	for _, url := range []string{"/api/v1/auth/revoke?token=" + admin, "/api/v1/auth/revoke?access_token=" + admin} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("POST", url, strings.NewReader(`{}`)))
		if w.Code != 401 {
			t.Fatalf("URL auth: %d", w.Code)
		}
	}
}

func TestApprovalExpiryWrongScopeActorAndConcurrentReplay(t *testing.T) {
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "replay.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	store, err := NewSQLReplayStore(context.Background(), db)
	if err != nil {
		t.Fatal(err)
	}
	scope := Scope{Tenant: "one", App: "web", Environment: "prod", Target: "edge"}
	a, err := NewApprovals(key, store, []Protected{{Deploy, Scope{Tenant: "*", App: "*", Environment: "*", Target: "*"}}})
	if err != nil {
		t.Fatal(err)
	}
	actor := Principal{ID: "agent", Grants: []Grant{{scope, []Action{Deploy}}}}
	op := Principal{ID: "operator", Grants: []Grant{{scope, []Action{Approve, Deploy}}}}
	r := ApprovalRequest{Actor: actor.ID, Action: Deploy, Scope: scope, Digest: Digest("exact CAS")}
	receipt, err := a.Issue(WithPrincipal(context.Background(), op), r)
	if err != nil {
		t.Fatal(err)
	}
	for _, foreign := range []Scope{{Tenant: "two", App: "web", Environment: "prod", Target: "edge"}, {Tenant: "one", App: "web", Environment: "prod", Target: "other"}} {
		if a.Check(WithPrincipal(context.Background(), actor), Deploy, foreign, r.Digest, receipt) == nil {
			t.Fatal("foreign receipt accepted")
		}
	}
	if a.Check(WithPrincipal(context.Background(), op), Deploy, scope, r.Digest, receipt) == nil {
		t.Fatal("wrong actor accepted")
	}
	now := time.Now()
	claims := approvalClaims{Claims: jwt.Claims{Issuer: "netcap-firewall", Audience: jwt.Audience{"firewall-approval"}, Subject: actor.ID, ID: "expired", IssuedAt: jwt.NewNumericDate(now.Add(-6 * time.Minute)), Expiry: jwt.NewNumericDate(now.Add(-time.Minute))}, Request: r, Approver: op.ID}
	signer, _ := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: key}, nil)
	expired, _ := jwt.Signed(signer).Claims(claims).Serialize()
	ctx := WithPrincipal(context.Background(), actor)
	if a.Check(ctx, Deploy, scope, r.Digest, expired) == nil {
		t.Fatal("expired receipt accepted")
	}
	var wins atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Go(func() {
			if a.Check(ctx, Deploy, scope, r.Digest, receipt) == nil {
				wins.Add(1)
			}
		})
	}
	wg.Wait()
	if wins.Load() != 1 {
		t.Fatalf("receipt consumed %d times", wins.Load())
	}
}
