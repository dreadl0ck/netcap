package responseactions

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/internal/policy"
)

func TestScopeVerifiedBeforeLeaseMutation(t *testing.T) {
	c, backend := controller(t, true)
	var mutations atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/leases" && r.Method == http.MethodPost {
			mutations.Add(1)
		}
		c.Handler().ServeHTTP(w, r)
	}))
	defer server.Close()
	config := configFor(t, server)
	scope := config.Scopes["edge"]
	scope.Network.Port = 8443
	config.Scopes["edge"] = scope
	b := newBroker(t, config)
	i := intent("192.0.2.5")
	b.Submit(i, i.Source)
	if receipt := await(t, b, i.ID, "failed"); receipt.Reason != "scope-mismatch" {
		t.Fatal(receipt)
	}
	leases, _ := backend.List(context.Background())
	if mutations.Load() != 0 || len(leases) != 0 {
		t.Fatalf("wrong scope was mutated: %d %+v", mutations.Load(), leases)
	}
}

func TestCreationRateTargetReservationsAndTTLBounds(t *testing.T) {
	c, _ := controller(t, true)
	var posts atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/leases" && r.Method == http.MethodPost {
			posts.Add(1)
		}
		c.Handler().ServeHTTP(w, r)
	}))
	defer server.Close()
	config := configFor(t, server)
	config.MaxActionsPerMinute = 2
	config.MaxPending = 64
	b := newBroker(t, config)
	tooLong := intent("192.0.2.250")
	tooLong.TTL = policy.MaxEffectTTL + time.Second
	tooLong.ExpiresAt = tooLong.IssuedAt.Add(tooLong.TTL)
	tooLong.ID = policy.IntentID(tooLong)
	if r := b.Submit(tooLong, tooLong.Source); r.Reason != "invalid-intent" {
		t.Fatal(r)
	}
	var wg sync.WaitGroup
	var admitted atomic.Int32
	var rateDropped atomic.Int32
	for n := 1; n <= 20; n++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			i := intent(fmt.Sprintf("192.0.2.%d", n))
			i.TTL = policy.MaxEffectTTL
			i.ExpiresAt = i.IssuedAt.Add(i.TTL)
			i.ID = policy.IntentID(i)
			r := b.Submit(i, i.Source)
			if r.Status == "requested" {
				admitted.Add(1)
			} else if r.Reason == "creation-rate" {
				rateDropped.Add(1)
			} else {
				t.Errorf("unexpected admission: %+v", r)
			}
		}(n)
	}
	wg.Wait()
	if admitted.Load() != 2 || rateDropped.Load() != 18 {
		t.Fatalf("admitted=%d rate-dropped=%d", admitted.Load(), rateDropped.Load())
	}
	for _, r := range b.Receipts() {
		if r.Status == "requested" {
			await(t, b, r.ID, "simulated")
		}
	}
	b.mu.Lock()
	if len(b.seen) != 2 || len(b.targets) != 2 {
		t.Errorf("unbounded admission state: %d %d", len(b.seen), len(b.targets))
	}
	var reserved targetKey
	var reservation targetReservation
	for key, value := range b.targets {
		reserved, reservation = key, value
		break
	}
	b.mu.Unlock()
	otherRule := intent(reserved.source)
	otherRule.RuleID = "different-rule"
	otherRule.Revision = strings.Repeat("b", 64)
	otherRule.ID = policy.IntentID(otherRule)
	if r := b.Submit(otherRule, otherRule.Source); r.Status != "duplicate" || r.Reason != "target-reserved" || r.ID != reservation.id || !r.ExpiresAt.Equal(reservation.expires) {
		t.Fatal(r)
	}
	if posts.Load() != 2 {
		t.Fatalf("unexpected lease creations: %d", posts.Load())
	}
	b.mu.Lock()
	b.actionWindow = time.Now().Add(-time.Minute - time.Second)
	b.mu.Unlock()
	i := intent("192.0.2.200")
	if r := b.Submit(i, i.Source); r.Status != "requested" {
		t.Fatal(r)
	}
	await(t, b, i.ID, "simulated")
	b.mu.Lock()
	b.prune(time.Now().Add(policy.MaxEffectTTL + b.retention + time.Second))
	remaining := len(b.seen) + len(b.targets)
	b.mu.Unlock()
	if remaining != 0 {
		t.Fatal("expired target/intent state retained")
	}
}

func TestWrapperPreservesRequiresBody(t *testing.T) {
	p, err := policy.Compile(policy.Bundle{Version: "1", ID: "body", Mode: "enforce", Default: "allow", Rules: []policy.Rule{{ID: "response", Action: "allow", Phase: "response", Expression: `lower(Body) == "x"`}}})
	if err != nil {
		t.Fatal(err)
	}
	wrapper := &Evaluator{Policy: p}
	if wrapper.RequiresBody("request") || !wrapper.RequiresBody("response") || wrapper.RequiresBody("unknown") {
		t.Fatal("wrapper masked body dependencies")
	}
}
