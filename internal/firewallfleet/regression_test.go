package firewallfleet

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func TestHTTPScopedReads(t *testing.T) {
	s, err := New(fleetConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()
	for _, op := range []string{"status", "audit", "capabilities"} {
		for _, tc := range []struct {
			name, token, query string
			want               int
		}{
			{"root", adminToken, "?tenant=tenant-a&app=app", 200},
			{"scoped-derived", "tenant-a-admin-token", "", 200},
			{"scoped-explicit", "tenant-a-admin-token", "?tenant=tenant-a&app=app", 200},
			{"foreign", "tenant-a-admin-token", "?tenant=tenant-b&app=app", 403},
			{"target", targetToken, "?tenant=tenant-a&app=app", 401},
		} {
			t.Run(op+"/"+tc.name, func(t *testing.T) {
				req, err := http.NewRequest("GET", srv.URL+"/api/v1/fleet/"+op+tc.query, nil)
				if err != nil {
					t.Fatal(err)
				}
				req.Header.Set("Authorization", "Bearer "+tc.token)
				resp, err := srv.Client().Do(req)
				if err != nil {
					t.Fatal(err)
				}
				defer resp.Body.Close()
				raw, err := io.ReadAll(resp.Body)
				if err != nil {
					t.Fatal(err)
				}
				if resp.StatusCode != tc.want {
					t.Fatalf("GET %s: %d %s", op, resp.StatusCode, raw)
				}
				if tc.want == 200 && op == "status" {
					var status Status
					if err = json.Unmarshal(raw, &status); err != nil {
						t.Fatal(err)
					}
					if len(status.Targets) != 2 || status.Targets["foreign"] != nil {
						t.Fatalf("foreign target leaked: %s", raw)
					}
				}
			})
		}
	}
}

func TestAgentMaxStaleWhileNetworkBlocked(t *testing.T) {
	for _, path := range []string{"desired", "ack"} {
		t.Run(path, func(t *testing.T) {
			s, _, _ := initializedFleet(t)
			defer s.Close()
			handler := s.Handler()
			var block atomic.Bool
			entered := make(chan struct{}, 1)
			release := make(chan struct{})
			defer func() {
				select {
				case <-release:
				default:
					close(release)
				}
			}()
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if block.Load() && r.URL.Path == "/api/v1/fleet/"+path {
					select {
					case entered <- struct{}{}:
					default:
					}
					select {
					case <-release:
					case <-r.Context().Done():
						return
					}
				}
				handler.ServeHTTP(w, r)
			}))
			defer srv.Close()
			var latest atomic.Pointer[AgentStatus]
			var callbacks, inCallback atomic.Int64
			var overlap atomic.Bool
			cfg := AgentConfig{URL: srv.URL, Token: targetToken, TargetID: "a", Scope: scopeA, StateDir: filepath.Join(t.TempDir(), "agent"), PollInterval: 10 * time.Millisecond, RequestTimeout: 500 * time.Millisecond, MaxStale: 40 * time.Millisecond, OnStatus: func(status AgentStatus) {
				if inCallback.Add(1) != 1 {
					overlap.Store(true)
				}
				defer inCallback.Add(-1)
				latest.Store(&status)
				callbacks.Add(1)
				time.Sleep(time.Millisecond)
			}}
			statuses, stop := startAgent(t, cfg, &atomicTarget{})
			stopped := false
			defer func() {
				if !stopped {
					stop()
				}
			}()
			awaitStatus(t, statuses, func(s AgentStatus) bool { return s.Ready })
			block.Store(true)
			select {
			case <-entered:
			case <-time.After(time.Second):
				t.Fatal("network request did not block")
			}
			stale := awaitStatus(t, statuses, func(s AgentStatus) bool { return !s.Ready && s.Generation == 1 })
			if age := time.Since(stale.LastContact); age > 200*time.Millisecond {
				t.Fatalf("expiry waited for network timeout: %s", age)
			}
			if latest.Load().Ready {
				t.Fatal("latest status remained ready")
			}
			block.Store(false)
			close(release)
			awaitStatus(t, statuses, func(s AgentStatus) bool { return s.Ready && s.LastContact.After(stale.LastContact) })
			stop()
			stopped = true
			count := callbacks.Load()
			time.Sleep(2 * cfg.MaxStale)
			if callbacks.Load() != count {
				t.Fatal("status callback after Run returned")
			}
			if overlap.Load() {
				t.Fatal("concurrent status callbacks")
			}
		})
	}
}

func TestStaleRefreshCannotReadyRevokedTarget(t *testing.T) {
	s, _, _ := initializedFleet(t)
	defer s.Close()
	execute(t, s, "revoke", Request{Targets: []string{"a"}, Expected: map[string]int64{"a": 1}})
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()
	var violation atomic.Bool
	statuses, stop := startAgent(t, AgentConfig{URL: srv.URL, Token: targetToken, TargetID: "a", Scope: scopeA, StateDir: filepath.Join(t.TempDir(), "agent"), PollInterval: 10 * time.Millisecond, MaxStale: 20 * time.Millisecond, OnStatus: func(s AgentStatus) {
		if s.Ready {
			violation.Store(true)
		}
	}}, &atomicTarget{})
	defer stop()
	first := awaitStatus(t, statuses, func(s AgentStatus) bool { return s.Revoked && !s.LastContact.IsZero() })
	awaitStatus(t, statuses, func(s AgentStatus) bool { return s.Revoked && s.LastContact.After(first.LastContact) })
	if violation.Load() {
		t.Fatal("fresh contact made revoked target ready")
	}
}
