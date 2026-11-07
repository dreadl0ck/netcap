package responseactions

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/internal/policy"
)

func TestAbsoluteDeadlineThroughRealEnforcer(t *testing.T) {
	for _, tc := range []struct {
		name       string
		ttl, delay time.Duration
		applied    bool
	}{
		{"one-second", time.Second, 0, true},
		{"delayed-post", 10 * time.Second, 1200 * time.Millisecond, true},
		{"expired-in-transit", time.Second, 1200 * time.Millisecond, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, backend := controller(t, true)
			handler := c.Handler()
			done := make(chan int, 1)
			var posts atomic.Int32
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPost || r.URL.Path != "/v1/leases" {
					handler.ServeHTTP(w, r)
					return
				}
				posts.Add(1)
				time.Sleep(tc.delay)
				capture := httptest.NewRecorder()
				handler.ServeHTTP(capture, r)
				for name, values := range capture.Header() {
					w.Header()[name] = values
				}
				w.WriteHeader(capture.Code)
				_, _ = w.Write(capture.Body.Bytes())
				done <- capture.Code
			}))
			defer server.Close()
			b := newBroker(t, configFor(t, server))
			i := intent("192.0.2.5")
			i.TTL = tc.ttl
			i.ExpiresAt = i.IssuedAt.Add(tc.ttl)
			i.ID = policy.IntentID(i)
			if r := b.Submit(i, i.Source); r.Status != "requested" {
				t.Fatal(r)
			}
			status := "failed"
			if tc.applied {
				status = "applied"
			}
			await(t, b, i.ID, status)
			select {
			case code := <-done:
				if tc.applied && code != http.StatusCreated {
					t.Fatalf("POST status %d", code)
				}
				if !tc.applied && code != http.StatusBadRequest {
					t.Fatalf("expired POST status %d", code)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("enforcer handler did not finish")
			}
			leases, err := backend.List(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if tc.applied {
				if len(leases) != 1 || !leases[0].ExpiresAt.Equal(i.ExpiresAt) {
					t.Fatalf("deadline changed: intent=%s leases=%+v", i.ExpiresAt, leases)
				}
			} else if len(leases) != 0 {
				t.Fatalf("expired intent mutated backend: %+v", leases)
			}
			if posts.Load() != 1 {
				t.Fatalf("unexpected POSTs: %d", posts.Load())
			}
		})
	}
}

func TestExpiredIntentRejectedBeforeHTTP(t *testing.T) {
	c, _ := controller(t, true)
	var calls atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); c.Handler().ServeHTTP(w, r) }))
	defer server.Close()
	b := newBroker(t, configFor(t, server))
	i := intent("192.0.2.5")
	i.TTL = time.Second
	i.IssuedAt = time.Now().UTC().Add(-2 * time.Second)
	i.ExpiresAt = i.IssuedAt.Add(i.TTL)
	i.ID = policy.IntentID(i)
	if r := b.Submit(i, i.Source); r.Status != "failed" || r.Reason != "invalid-intent" {
		t.Fatal(r)
	}
	if calls.Load() != 0 {
		t.Fatal("expired intent sent HTTP")
	}
}
