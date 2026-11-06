package enforcer

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestMCPLeaseLifecycle(t *testing.T) {
	c := controller(t, testConfig(), nil)
	h := c.Handler()
	call := func(raw string, authorized bool) map[string]any {
		t.Helper()
		r := httptest.NewRequest("POST", "/mcp", strings.NewReader(raw))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Accept", "application/json, text/event-stream")
		if authorized {
			r.Header.Set("Authorization", "Bearer "+testConfig().Token)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if !authorized {
			if w.Code != 401 {
				t.Fatalf("unauthenticated status %d", w.Code)
			}
			return nil
		}
		if w.Code != 200 {
			t.Fatalf("MCP status %d: %s", w.Code, w.Body.String())
		}
		var response map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
			t.Fatal(err, w.Body.String())
		}
		if response["error"] != nil {
			t.Fatalf("protocol error: %v", response)
		}
		return response["result"].(map[string]any)
	}
	init := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}`
	call(init, false)
	call(init, true)
	tools := call(`{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}`, true)
	if len(tools["tools"].([]any)) != 4 {
		t.Fatalf("tool inventory: %v", tools)
	}
	invoke := func(name, args string) map[string]any {
		return call(`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"`+name+`","arguments":`+args+`}}`, true)
	}
	for _, args := range []string{`{"id":"bad","source":"192.0.2.1","ttl_seconds":60}`, `{"id":"bad","source":"198.51.100.1","ttl_seconds":901}`, `{"id":"bad","source":"198.51.100.1","ttl_seconds":60,"scope":"all"}`} {
		if invoke("create_action_lease", args)["isError"] != true {
			t.Fatal("unsafe lease accepted", args)
		}
	}
	if result := invoke("create_action_lease", `{"id":"incident","source":"198.51.100.1","ttl_seconds":60}`); result["isError"] == true {
		t.Fatal(result)
	}
	leases, err := c.List(t.Context())
	if err != nil || len(leases) != 1 {
		t.Fatal(leases, err)
	}
	if result := invoke("revoke_action_lease", `{"id":"incident"}`); result["isError"] == true {
		t.Fatal(result)
	}
	leases, err = c.List(t.Context())
	if err != nil || len(leases) != 0 {
		t.Fatal(leases, err)
	}
}
