package firewallaudit

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/internal/enforcer"
	"github.com/dreadl0ck/netcap/internal/policy"
	"github.com/dreadl0ck/netcap/internal/responseactions"
	"github.com/dreadl0ck/netcap/types"
	"github.com/gogo/protobuf/proto"
)

func writeJSON(t *testing.T, name string, v any) string {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), name)
	if err = os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func fixtureBundle(expression string) policy.Bundle {
	return policy.Bundle{Version: "1", ID: "native-audit", Mode: "enforce", Default: "allow", Rules: []policy.Rule{{ID: "future-block", Expression: expression, Action: "deny", Effects: []policy.Effect{{Kind: "block_source", Target: "source", Duration: "30s", Scope: "edge"}}}}}
}

func TestLiveBrokerAndReplayAreSeparated(t *testing.T) {
	backend := enforcer.NewDryRunBackend()
	scope := enforcer.Scope{Hook: "input", Interface: "eth0", DestinationCIDR: "198.51.100.0/24", Protocol: "tcp", Port: 445}
	controller, err := enforcer.New(enforcer.Config{Token: strings.Repeat("t", 32), Scope: scope}, backend)
	if err != nil {
		t.Fatal(err)
	}
	defer controller.Close()
	var calls atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); controller.Handler().ServeHTTP(w, r) }))
	defer server.Close()
	t.Setenv("FIREWALL_AUDIT_TEST_TOKEN", strings.Repeat("t", 32))
	ca := filepath.Join(t.TempDir(), "ca.pem")
	if err = os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	effects := writeJSON(t, "effects.json", ConfigJSON{Scopes: map[string]responseactions.Scope{"edge": {Endpoint: server.URL, TokenEnv: "FIREWALL_AUDIT_TEST_TOKEN", Network: scope}}, CA: ca})
	b := fixtureBundle("Protocol == 'audit' && RecordType == 'SMB' && Fields['ShareName'] == 'ADMIN$'")
	path := writeJSON(t, "policy.json", b)
	for _, live := range []bool{false, true} {
		if live {
			t.Setenv("FIREWALL_AUDIT_TEST_TOKEN", strings.Repeat("t", 32))
		} else {
			t.Setenv("FIREWALL_AUDIT_TEST_TOKEN", "")
		}
		var audit bytes.Buffer
		r, err := Open(Config{PolicyFile: path, EffectsFile: effects, Live: live, Audit: &audit})
		if err != nil {
			t.Fatal(err)
		}
		if (r.broker != nil) != live {
			t.Fatal("replay created a broker")
		}
		before := calls.Load()
		result := r.Observe(&types.SMB{SrcIP: "192.0.2.5", ShareName: "ADMIN$", Username: "private-user"}, nil)
		if result.Decision.RuleID != "future-block" || len(result.Decision.Effects) != 0 || result.Phase != "retrospective" || result.DryRun == live {
			t.Fatalf("result: %+v", result)
		}
		if !live {
			if result.EffectsRequested != 0 || calls.Load() != before {
				t.Fatal("replay performed network response")
			}
		} else {
			if result.EffectsRequested != 1 {
				t.Fatalf("live response not admitted: %+v receipts=%+v", result, r.broker.Receipts())
			}
			deadline := time.Now().Add(5 * time.Second)
			for {
				leases, _ := backend.List(context.Background())
				if len(leases) == 1 {
					if leases[0].Source != "192.0.2.5" {
						t.Fatal(leases)
					}
					break
				}
				if time.Now().After(deadline) {
					t.Fatalf("no simulated future-block lease: %+v", r.broker.Receipts())
				}
				time.Sleep(time.Millisecond)
			}
			if r.Observe(&types.SMB{SrcIP: "192.0.2.5", ShareName: "ADMIN$"}, nil).EffectsRequested != 0 {
				t.Fatal("duplicate response renewed lease")
			}
		}
		if err = r.Close(); err != nil {
			t.Fatal(err)
		}
		for _, secret := range []string{"ADMIN$", "private-user", "192.0.2.5", "Fields[", "block_source"} {
			if strings.Contains(audit.String(), secret) {
				t.Fatalf("audit leaked %s", secret)
			}
		}
	}
	// Matching source-less records must still classify, without creating intents.
	b = fixtureBundle("RecordType == 'SSH' && Fields['HasWeakCipher'] == 'true'")
	r, err := Open(Config{PolicyFile: writeJSON(t, "ssh.json", b), EffectsFile: effects, Live: true})
	if err != nil {
		t.Fatal(err)
	}
	before := calls.Load()
	result := r.Observe(&types.SSH{HasWeakCipher: true, Flow: "192.0.2.8:22", Ident: "192.0.2.8"}, nil)
	if result.Decision.RuleID != "future-block" || result.Reason != "source-unavailable" || result.EffectsRequested != 0 {
		t.Fatal(result)
	}
	if err = r.Close(); err != nil || calls.Load() != before {
		t.Fatal("source-less SSH contacted network", err)
	}
}

func TestAdmissionConcurrencyAndLegacyObserver(t *testing.T) {
	b := fixtureBundle("RecordType == 'SMTP' && Fields['Commands[0]'] == 'AUTH secret'")
	path := writeJSON(t, "policy.json", b)
	if _, err := Open(Config{PolicyFile: path}); err == nil {
		t.Fatal("effects admitted without operator config")
	}
	b.Rules[0].Effects = nil
	b.Rules[0].Threshold = &policy.Threshold{Count: 2, Window: "1m", GroupBy: "RecordType"}
	var audit bytes.Buffer
	r, err := Open(Config{PolicyFile: writeJSON(t, "policy.json", b), Audit: &audit})
	if err != nil {
		t.Fatal(err)
	}
	first := r.Observe(&types.SMTP{Commands: []string{"AUTH secret"}}, nil)
	second := r.Observe(&types.SMTP{Commands: []string{"AUTH secret"}}, nil)
	if first.Decision.RuleID != "" || second.Decision.RuleID != "future-block" {
		t.Fatal("replay reset threshold state")
	}
	var legacy atomic.Int32
	observe := r.Chain(func(m proto.Message) {
		if m.(*types.SMTP).Commands[0] == "AUTH secret" {
			legacy.Add(1)
		}
	})
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); observe(&types.SMTP{Commands: []string{"AUTH secret"}}) }()
	}
	wg.Wait()
	if legacy.Load() != 32 {
		t.Fatal("legacy observer lost")
	}
	if err = r.Close(); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(audit.String(), "AUTH secret") {
		t.Fatal("secret persisted")
	}
	if r.Observe(&types.SMTP{}, nil).Reason != "closed" {
		t.Fatal("closed runtime accepted record")
	}
	for _, expression := range []string{"Fields['invented.field'] == 'x'", "RecordType == 'Invented'", "Fields[Host] == 'x'"} {
		b.Rules[0].Expression = expression
		if _, err = Open(Config{PolicyFile: writeJSON(t, "invalid.json", b)}); err == nil {
			t.Fatalf("unknown capability admitted: %s", expression)
		}
	}
	if _, err = Open(Config{PolicyFile: path, SchemaVersion: "wrong"}); err == nil {
		t.Fatal("wrong schema version admitted")
	}
}

type stalledAudit struct {
	entered, release chan struct{}
	once             sync.Once
}

func (w *stalledAudit) Write(p []byte) (int, error) {
	w.once.Do(func() { close(w.entered) })
	<-w.release
	return len(p), nil
}

func TestAuditSinkCannotBlockObserverAndOverflowIsReported(t *testing.T) {
	b := fixtureBundle("RecordType == 'SMTP'")
	b.Rules[0].Effects = nil
	w := &stalledAudit{entered: make(chan struct{}), release: make(chan struct{})}
	r, err := Open(Config{PolicyFile: writeJSON(t, "policy.json", b), Audit: w})
	if err != nil {
		t.Fatal(err)
	}
	r.Observe(&types.SMTP{}, nil)
	<-w.entered
	finished := make(chan struct{})
	go func() {
		for i := 0; i < 300; i++ {
			r.Observe(&types.SMTP{}, nil)
		}
		close(finished)
	}()
	select {
	case <-finished:
	case <-time.After(5 * time.Second):
		close(w.release)
		_ = r.Close()
		t.Fatal("audit I/O blocked observation")
	}
	close(w.release)
	if r.DroppedAudit() == 0 || r.Close() == nil {
		t.Fatal("audit loss silently ignored")
	}
}
