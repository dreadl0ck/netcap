package firewallfleet

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/internal/firewallstate"
	"github.com/dreadl0ck/netcap/internal/policy"
)

type lifecycleTarget struct {
	ptr   atomic.Pointer[policy.Compiled]
	calls atomic.Int32
}

func (t *lifecycleTarget) Policy() *policy.Compiled     { return t.ptr.Load() }
func (t *lifecycleTarget) SetPolicy(c *policy.Compiled) { t.calls.Add(1); t.ptr.Store(c) }

func TestRunCancellationPublishesTerminalUnready(t *testing.T) {
	for _, maxStale := range []time.Duration{0, 200 * time.Millisecond} {
		t.Run(maxStale.String(), func(t *testing.T) {
			s, _, _ := initializedFleet(t)
			defer s.Close()
			var acked atomic.Bool
			handler := s.Handler()
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				handler.ServeHTTP(w, r)
				if r.URL.Path == "/api/v1/fleet/ack" {
					acked.Store(true)
				}
			}))
			defer srv.Close()
			var latest atomic.Pointer[AgentStatus]
			var callbacks atomic.Int32
			ready := make(chan struct{}, 1)
			cfg := AgentConfig{URL: srv.URL, Token: targetToken, TargetID: "a", Scope: scopeA, StateDir: filepath.Join(t.TempDir(), "agent"), PollInterval: time.Minute, MaxStale: maxStale, OnStatus: func(s AgentStatus) {
				latest.Store(&s)
				callbacks.Add(1)
				if s.Ready && acked.Load() {
					select {
					case ready <- struct{}{}:
					default:
					}
				}
			}}
			ctx, cancel := context.WithCancelCause(context.Background())
			defer cancel(nil)
			done := make(chan error, 1)
			go func() { done <- Run(ctx, cfg, &lifecycleTarget{}) }()
			select {
			case <-ready:
			case err := <-done:
				t.Fatalf("early exit: %v", err)
			case <-time.After(3 * time.Second):
				cancel(nil)
				<-done
				t.Fatal("agent never acknowledged ready policy")
			}
			cancel(errors.New("private-cancellation-cause-do-not-publish"))
			select {
			case err := <-done:
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("return error: %v", err)
				}
			case <-time.After(time.Second):
				t.Fatal("agent did not stop")
			}
			final := latest.Load()
			if final == nil || final.Ready || final.Error != context.Canceled.Error() || final.Generation != 1 {
				t.Fatalf("terminal status: %+v", final)
			}
			before := callbacks.Load()
			time.Sleep(max(20*time.Millisecond, 2*maxStale))
			if callbacks.Load() != before {
				t.Fatal("callback after Run returned")
			}
			if latest.Load() != final {
				t.Fatal("terminal status replaced after shutdown")
			}
		})
	}
}

func TestAlreadyCancelledRunDoesNotApplyOrPublishCache(t *testing.T) {
	for _, deadline := range []bool{false, true} {
		t.Run(map[bool]string{false: "cancelled", true: "expired"}[deadline], func(t *testing.T) {
			cfg := AgentConfig{URL: "http://127.0.0.1:1", Token: targetToken, TargetID: "a", Scope: scopeA, StateDir: filepath.Join(t.TempDir(), "agent")}
			if err := firewallstate.PrivateDir(cfg.StateDir); err != nil {
				t.Fatal(err)
			}
			allow, raw, err := compile([]byte(`{"version":"1","id":"cached-allow","mode":"enforce","default":"allow"}`))
			if err != nil {
				t.Fatal(err)
			}
			d := Desired{Version: 1, TargetID: "a", Scope: scopeA, Generation: 1, Revision: allow.Revision(), Hash: firewallstate.Digest(string(raw)), Bundle: raw}
			record := cacheRecord{Binding: agentBinding(cfg), Desired: d, Contact: time.Now().UTC()}
			record.MAC = signCache(record, cfg.Token)
			path := filepath.Join(cfg.StateDir, "agent-cache.json")
			if err = writeCache(path, record); err != nil {
				t.Fatal(err)
			}
			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			deny, _, err := compile([]byte(`{"version":"1","id":"initial-deny","mode":"enforce","default":"deny"}`))
			if err != nil {
				t.Fatal(err)
			}
			target := &lifecycleTarget{}
			target.ptr.Store(deny)
			var callbacks atomic.Int32
			cfg.OnStatus = func(AgentStatus) { callbacks.Add(1) }
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			want := context.Canceled
			if deadline {
				var stop context.CancelFunc
				ctx, stop = context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
				defer stop()
				want = context.DeadlineExceeded
			}
			if err = Run(ctx, cfg, target); !errors.Is(err, want) {
				t.Fatalf("return error: %v", err)
			}
			if target.calls.Load() != 0 || target.Policy() != deny || callbacks.Load() != 0 {
				t.Fatalf("pre-cancelled Run changed state: setters=%d callbacks=%d", target.calls.Load(), callbacks.Load())
			}
			after, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("pre-cancelled Run changed cache")
			}
			if _, err = os.Lstat(filepath.Join(cfg.StateDir, "agent.sqlite")); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("pre-cancelled Run opened agent state")
			}
		})
	}
}

type lifecycleTransport func(*http.Request) (*http.Response, error)

func (f lifecycleTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestCancellationDuringFetchDoesNotApplyPolicy(t *testing.T) {
	allow, raw, err := compile([]byte(`{"version":"1","id":"downloaded-allow","mode":"enforce","default":"allow"}`))
	if err != nil {
		t.Fatal(err)
	}
	d := Desired{Version: 1, TargetID: "a", Scope: scopeA, Generation: 1, Revision: allow.Revision(), Hash: firewallstate.Digest(string(raw)), Bundle: raw}
	body, _ := json.Marshal(d)
	deny, _, err := compile([]byte(`{"version":"1","id":"deny","mode":"enforce","default":"deny"}`))
	if err != nil {
		t.Fatal(err)
	}
	target := &lifecycleTarget{}
	target.ptr.Store(deny)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var latest AgentStatus
	cfg := AgentConfig{URL: "http://127.0.0.1:1", Token: targetToken, TargetID: "a", Scope: scopeA, StateDir: filepath.Join(t.TempDir(), "agent"), OnStatus: func(s AgentStatus) { latest = s }, Transport: lifecycleTransport(func(*http.Request) (*http.Response, error) {
		cancel()
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(body))}, nil
	})}
	if err = Run(ctx, cfg, target); !errors.Is(err, context.Canceled) {
		t.Fatalf("return error: %v", err)
	}
	if target.calls.Load() != 0 || target.Policy() != deny || latest.Ready || latest.Error != context.Canceled.Error() {
		t.Fatalf("cancelled fetch applied policy: calls=%d status=%+v", target.calls.Load(), latest)
	}
}
