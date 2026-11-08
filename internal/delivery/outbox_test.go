package delivery

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/types"
)

func TestRestartRetryIdempotencyAndRedaction(t *testing.T) {
	var mu sync.Mutex
	var keys []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		keys = append(keys, r.Header.Get("Idempotency-Key"))
		body, _ := io.ReadAll(r.Body)
		if strings.Contains(string(body), "fixture-secret") {
			t.Error("credential leaked")
		}
		var n Notice
		if json.Unmarshal(body, &n) != nil || n.Scope != "capture/source" {
			t.Error("invalid notice")
		}
		if r.Header.Get("Authorization") != "Bearer runtime-token" {
			t.Error("missing runtime auth")
		}
		if len(keys) == 1 {
			w.WriteHeader(503)
			return
		}
		w.WriteHeader(204)
	}))
	defer server.Close()
	dir := t.TempDir()
	o, err := Open(dir, server.URL)
	if err != nil {
		t.Fatal(err)
	}
	a := &types.Alert{Timestamp: 42, RuleName: "test", RuleDigest: "digest", MatchedRecordSHA256: "evidence", MatchedRecord: "fixture-secret", Notes: "fixture-secret", Description: "fixture-secret", RuleExpression: "fixture-secret"}
	id, err := o.Enqueue("capture/source", a)
	if err != nil {
		t.Fatal(err)
	}
	a.DetectedAt = 99
	if again, err := o.Enqueue("capture/source", a); err != nil || again != id {
		t.Fatal(again, err)
	}
	if err = o.Deliver(context.Background(), 10, "runtime-token"); err != nil {
		t.Fatal(err)
	}
	if s, _ := o.Status(); s.Pending != 1 {
		t.Fatal(s)
	}
	if err = o.Close(); err != nil {
		t.Fatal(err)
	}
	o, err = Open(dir, server.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer o.Close()
	if err = o.Deliver(context.Background(), 10, "runtime-token"); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	n := len(keys)
	mu.Unlock()
	if n != 1 {
		t.Fatal("persisted retry delay lost")
	}
	time.Sleep(1100 * time.Millisecond)
	if err = o.Deliver(context.Background(), 10, "runtime-token"); err != nil {
		t.Fatal(err)
	}
	if s, _ := o.Status(); s.Delivered != 1 || s.RequireDrained() != nil {
		t.Fatal(s)
	}
	if _, err = o.Enqueue("capture/source", a); err != nil {
		t.Fatal(err)
	}
	if err = o.Deliver(context.Background(), 10, "runtime-token"); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(keys) != 2 || keys[0] != id || keys[1] != id {
		t.Fatal(keys)
	}
	data, err := os.ReadFile(filepath.Join(dir, "alert-outbox.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "fixture-secret") || strings.Contains(string(data), "runtime-token") {
		t.Fatal("secret persisted")
	}
	if other, err := Open(dir, server.URL+"/other"); err == nil {
		other.Close()
		t.Fatal("destination switched")
	}
}

func TestRejectedRedirectCapacityAndCancellation(t *testing.T) {
	var redirected bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/target" {
			redirected = true
		}
		w.Header().Set("Location", "/target")
		w.WriteHeader(302)
	}))
	defer server.Close()
	o, err := Open(t.TempDir(), server.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer o.Close()
	if _, err = o.Enqueue("scope", &types.Alert{RuleName: "test"}); err != nil {
		t.Fatal(err)
	}
	if err = o.Deliver(context.Background(), 1, ""); err != nil {
		t.Fatal(err)
	}
	if s, _ := o.Status(); s.Rejected != 1 || s.RequireDrained() == nil || redirected {
		t.Fatal(s, redirected)
	}
	_, err = o.db.Exec(`WITH RECURSIVE n(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM n WHERE x<9999) INSERT INTO notices(id,payload) SELECT 'filler-'||x,'{}' FROM n`)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = o.Enqueue("other", &types.Alert{RuleName: "new"}); !errors.Is(err, ErrFull) {
		t.Fatal(err)
	}
	if _, err = o.Enqueue("scope", &types.Alert{RuleName: "test"}); err != nil {
		t.Fatal("receipt lookup at capacity", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err = o.Deliver(ctx, 1, ""); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestConcurrentEnqueue(t *testing.T) {
	o, err := Open(t.TempDir(), "http://127.0.0.1:1")
	if err != nil {
		t.Fatal(err)
	}
	defer o.Close()
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := o.Enqueue("scope", &types.Alert{RuleName: "same"}); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if s, _ := o.Status(); s.Pending != 1 {
		t.Fatal(s)
	}
}

func TestLegacyAlertCoordinatesDoNotCollapse(t *testing.T) {
	o, err := Open(t.TempDir(), "http://127.0.0.1:1")
	if err != nil {
		t.Fatal(err)
	}
	defer o.Close()
	for _, src := range []string{"192.0.2.1", "192.0.2.2"} {
		if _, err := o.Enqueue("scope", &types.Alert{RuleName: "legacy", Timestamp: 1, SrcIP: src}); err != nil {
			t.Fatal(err)
		}
	}
	if s, _ := o.Status(); s.Pending != 2 {
		t.Fatal("unrelated legacy alerts collapsed", s)
	}
}

func TestAcceptedBeforeReceiptCommitCanBeDeduplicated(t *testing.T) {
	seen := map[string]bool{}
	posts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		posts++
		seen[r.Header.Get("Idempotency-Key")] = true
		w.WriteHeader(204)
	}))
	defer server.Close()
	dir := t.TempDir()
	o, err := Open(dir, server.URL)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = o.Enqueue("scope", &types.Alert{RuleName: "one"}); err != nil {
		t.Fatal(err)
	}
	if err = o.Deliver(context.Background(), 1, ""); err != nil {
		t.Fatal(err)
	}
	// Model termination after the remote ACK and before the local receipt commit.
	if _, err = o.db.Exec(`UPDATE notices SET state='pending',due=0`); err != nil {
		t.Fatal(err)
	}
	o.Close()
	o, err = Open(dir, server.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer o.Close()
	if err = o.Deliver(context.Background(), 1, ""); err != nil {
		t.Fatal(err)
	}
	if posts != 2 || len(seen) != 1 {
		t.Fatal("receiver cannot deduplicate interrupted ACK", posts, len(seen))
	}
}
