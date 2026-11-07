package enforcer

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type deadlineBackend struct {
	*DryRunBackend
	applies   atomic.Int32
	lists     atomic.Int32
	listDelay time.Duration
	deadline  time.Time
}

func (b *deadlineBackend) List(ctx context.Context) ([]Lease, error) {
	b.lists.Add(1)
	time.Sleep(b.listDelay)
	return b.DryRunBackend.List(ctx)
}

func (b *deadlineBackend) Apply(ctx context.Context, l Lease) error {
	b.applies.Add(1)
	b.deadline, _ = ctx.Deadline()
	return b.DryRunBackend.Apply(ctx, l)
}

func TestCreateUntilBoundsSubsecondAndRetry(t *testing.T) {
	cfg := testConfig()
	cfg.DryRun = false
	b := &deadlineBackend{DryRunBackend: NewDryRunBackend()}
	c := controller(t, cfg, b)
	for _, deadline := range []time.Time{{}, time.Now().Add(-time.Second), time.Now().Add(500 * time.Microsecond), time.Now().Add(HardMaxTTL + time.Second)} {
		lists := b.lists.Load()
		if _, err := c.CreateUntil(context.Background(), "invalid", "198.51.100.1", deadline); err == nil {
			t.Fatalf("accepted deadline %s", deadline)
		}
		if b.applies.Load() != 0 || b.lists.Load() != lists {
			t.Fatal("invalid deadline reached reconciliation/backend")
		}
	}
	deadline := time.Now().Add(1500 * time.Millisecond)
	first, err := c.CreateUntil(context.Background(), "absolute", "198.51.100.1", deadline)
	if err != nil {
		t.Fatal(err)
	}
	if !first.ExpiresAt.Equal(deadline) || first.TTLSeconds != 2 || !b.deadline.Equal(deadline) {
		t.Fatalf("changed deadline/context: %+v %s", first, b.deadline)
	}
	time.Sleep(600 * time.Millisecond)
	// The remaining lifetime now rounds to one second, but retry keeps metadata.
	again, err := c.CreateUntil(context.Background(), first.ID, first.Source, deadline)
	if err != nil || again != first || b.applies.Load() != 1 {
		t.Fatalf("retry renewed/reapplied: %+v %v", again, err)
	}
	if _, err := c.CreateUntil(context.Background(), first.ID, first.Source, deadline.Add(time.Second)); !errors.Is(err, ErrConflict) {
		t.Fatalf("deadline extension accepted: %v", err)
	}
	if _, err := c.CreateUntil(context.Background(), first.ID, "198.51.100.2", deadline); !errors.Is(err, ErrConflict) {
		t.Fatalf("source change accepted: %v", err)
	}
	if _, err := c.CreateUntil(context.Background(), "protected", "192.0.2.1", deadline); err == nil {
		t.Fatal("protected source accepted")
	}
	if err := c.Delete(context.Background(), first.ID); err != nil {
		t.Fatal(err)
	}
	subsecond := time.Now().Add(750 * time.Millisecond)
	l, err := c.CreateUntil(context.Background(), "subsecond", "198.51.100.1", subsecond)
	if err != nil || l.TTLSeconds != 1 || !l.ExpiresAt.Equal(subsecond) {
		t.Fatalf("subsecond deadline not preserved: %+v %v", l, err)
	}
}

func TestCreateUntilExpiryDuringReconcileDoesNotApply(t *testing.T) {
	cfg := testConfig()
	cfg.DryRun = false
	b := &deadlineBackend{DryRunBackend: NewDryRunBackend()}
	c := controller(t, cfg, b)
	b.listDelay = 100 * time.Millisecond
	if _, err := c.CreateUntil(context.Background(), "expired", "198.51.100.1", time.Now().Add(50*time.Millisecond)); err == nil {
		t.Fatal("deadline expiring during reconcile accepted")
	}
	if b.applies.Load() != 0 || len(c.leases) != 0 {
		t.Fatal("expired deadline created backend or desired state")
	}
}

func TestCreateUntilFractionalLimitAndPersistence(t *testing.T) {
	cfg := testConfig()
	cfg.DryRun = false
	cfg.MaxTTL = 1500 * time.Millisecond
	cfg.StateFile = filepath.Join(t.TempDir(), "leases.json")
	b := NewDryRunBackend()
	c := controller(t, cfg, b)
	deadline := time.Now().Add(1200 * time.Millisecond)
	l, err := c.CreateUntil(context.Background(), "fractional", "198.51.100.1", deadline)
	if err != nil || l.TTLSeconds != 2 {
		t.Fatalf("fractional configured limit failed: %+v %v", l, err)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	// Recover absent backend state using the original absolute timestamp.
	b = NewDryRunBackend()
	restored := controller(t, cfg, b)
	leases, err := restored.List(context.Background())
	if err != nil || len(leases) != 1 || leases[0] != l {
		t.Fatalf("restart altered deadline: %+v %v", leases, err)
	}
}

func TestAbsoluteDeadlineRESTSchema(t *testing.T) {
	c := controller(t, testConfig(), nil)
	h := c.Handler()
	post := func(body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, "/v1/leases", strings.NewReader(body))
		r.Header.Set("Authorization", "Bearer "+testConfig().Token)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	deadline := time.Now().UTC().Add(10 * time.Second)
	raw, _ := json.Marshal(map[string]any{"id": "absolute", "source": "198.51.100.1", "expires_at": deadline, "ttl_seconds": 10})
	first := post(string(raw))
	if first.Code != 201 {
		t.Fatal(first.Code, first.Body.String())
	}
	var lease Lease
	if err := json.Unmarshal(first.Body.Bytes(), &lease); err != nil || !lease.ExpiresAt.Equal(deadline) {
		t.Fatalf("deadline: %+v %v", lease, err)
	}
	second := post(string(raw))
	if second.Code != 201 || second.Body.String() != first.Body.String() {
		t.Fatal("absolute HTTP retry changed receipt")
	}
	for _, body := range []string{
		`{"id":"bad","source":"198.51.100.2"}`,
		`{"id":"bad","source":"198.51.100.2","ttl_seconds":0,"expires_at":"` + deadline.Format(time.RFC3339Nano) + `"}`,
		`{"id":"bad","source":"198.51.100.2","ttl_seconds":1,"expires_at":"` + deadline.Format(time.RFC3339Nano) + `"}`,
		`{"id":"bad","source":"198.51.100.2","ttl_seconds":901,"expires_at":"` + deadline.Format(time.RFC3339Nano) + `"}`,
		`{"id":"bad","source":"198.51.100.2","ttl_seconds":10,"expires_at":null}`,
		`{"id":"bad","source":"198.51.100.2","ttl_seconds":null,"expires_at":"` + deadline.Format(time.RFC3339Nano) + `"}`,
		`{"id":"bad","source":"198.51.100.2","expires_at":"not-a-time"}`,
		`{"id":"bad","source":"198.51.100.2","expires_at":"0001-01-01T00:00:00Z"}`,
		`{"id":"bad","source":"198.51.100.2","expires_at":"2000-01-01T00:00:00Z"}`,
		`{"id":"bad","source":"198.51.100.2","expires_at":"` + deadline.Format(time.RFC3339Nano) + `","expires_at":"` + deadline.Format(time.RFC3339Nano) + `"}`,
	} {
		if w := post(body); w.Code != 400 {
			t.Fatalf("accepted invalid lifetime %s: %d %s", body, w.Code, w.Body.String())
		}
	}
	raw, _ = json.Marshal(map[string]any{"id": "absolute-only", "source": "198.51.100.2", "expires_at": deadline})
	if w := post(string(raw)); w.Code != 201 {
		t.Fatal("absolute-only request failed", w.Code, w.Body.String())
	}
	leases, err := c.List(context.Background())
	if err != nil || len(leases) != 2 {
		t.Fatalf("invalid request mutated state: %+v %v", leases, err)
	}
}

func TestAbsoluteDeadlineMCPAndSchema(t *testing.T) {
	c := controller(t, testConfig(), nil)
	h := c.Handler()
	call := func(method string, params any) json.RawMessage {
		t.Helper()
		raw, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
		if err != nil {
			t.Fatal(err)
		}
		r := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(string(raw)))
		r.Header.Set("Authorization", "Bearer "+testConfig().Token)
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Accept", "application/json, text/event-stream")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		var envelope struct {
			Result json.RawMessage `json:"result"`
			Error  json.RawMessage `json:"error"`
		}
		if w.Code != 200 {
			t.Fatal(w.Code, w.Body.String())
		}
		if err := json.Unmarshal(w.Body.Bytes(), &envelope); err != nil || len(envelope.Error) > 0 {
			t.Fatalf("MCP response: %s %v", w.Body.String(), err)
		}
		return envelope.Result
	}
	var inventory struct {
		Tools []struct {
			Name   string `json:"name"`
			Schema struct {
				Properties map[string]struct {
					Type   string `json:"type"`
					Format string `json:"format"`
				} `json:"properties"`
				Required []string          `json:"required"`
				AnyOf    []json.RawMessage `json:"anyOf"`
			} `json:"inputSchema"`
		} `json:"tools"`
	}
	if err := json.Unmarshal(call("tools/list", map[string]any{}), &inventory); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, tool := range inventory.Tools {
		if tool.Name == "create_action_lease" {
			found = true
			if tool.Schema.Properties["expires_at"].Type != "string" || tool.Schema.Properties["expires_at"].Format != "date-time" || len(tool.Schema.Required) != 2 || len(tool.Schema.AnyOf) != 2 {
				t.Fatalf("incorrect absolute lifetime schema: %+v", tool.Schema)
			}
		}
	}
	if !found {
		t.Fatal("missing create tool")
	}
	invoke := func(name string, args any) (bool, string) {
		t.Helper()
		var result struct {
			IsError bool `json:"isError"`
			Content []struct {
				Text string `json:"text"`
			} `json:"content"`
		}
		if err := json.Unmarshal(call("tools/call", map[string]any{"name": name, "arguments": args}), &result); err != nil || len(result.Content) != 1 {
			t.Fatalf("result %+v %v", result, err)
		}
		return result.IsError, result.Content[0].Text
	}
	failed, text := invoke("get_enforcer_capabilities", map[string]any{})
	var capabilities enforcerCapabilities
	if err := json.Unmarshal([]byte(text), &capabilities); err != nil || failed || !capabilities.AbsoluteDeadlines {
		t.Fatalf("deadline capability missing: %s %v", text, err)
	}
	deadline := time.Now().UTC().Add(5 * time.Second)
	args := map[string]any{"id": "mcp-absolute", "source": "198.51.100.1", "expires_at": deadline.Format(time.RFC3339Nano)}
	failed, text = invoke("create_action_lease", args)
	var first Lease
	if err := json.Unmarshal([]byte(text), &first); err != nil || failed || !first.ExpiresAt.Equal(deadline) {
		t.Fatalf("MCP deadline changed: %s %v", text, err)
	}
	failed, text = invoke("create_action_lease", args)
	var second Lease
	if err := json.Unmarshal([]byte(text), &second); err != nil || failed || second != first {
		t.Fatalf("MCP retry renewed deadline: %s %v", text, err)
	}
	args["ttl_seconds"] = 1
	if failed, _ := invoke("create_action_lease", args); !failed {
		t.Fatal("MCP accepted inconsistent TTL/deadline")
	}
	delete(args, "ttl_seconds")
	args["expires_at"] = nil
	if failed, _ := invoke("create_action_lease", args); !failed {
		t.Fatal("MCP accepted null deadline")
	}
	delete(args, "expires_at")
	if failed, _ := invoke("create_action_lease", args); !failed {
		t.Fatal("MCP accepted missing lifetime")
	}
}
