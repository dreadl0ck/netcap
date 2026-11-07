package enforcer

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func actionConfig() Config {
	c := testConfig()
	c.ProtectedCIDRs = nil
	c.ProtectedServices = []Service{{"tcp", 22}}
	c.Profiles = map[string]Profile{
		"isolate": {Kind: Quarantine, Services: []Service{{"tcp", 443}, {"udp", 53}}},
		"packets": {Kind: RateSource, Services: []Service{{"udp", 53}}, Unit: "packets", Rate: 10, Burst: 3},
	}
	return c
}

func TestLegacyAuthorityFingerprint(t *testing.T) {
	cfg, _, err := normalize(testConfig())
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(struct {
		Table, Namespace string
		Scope            Scope
		Protected        []string
		DryRun           bool
	}{cfg.Table, cfg.Namespace, cfg.Scope, cfg.ProtectedCIDRs, cfg.DryRun})
	h := sha256.Sum256(raw)
	if fingerprint(cfg) != hex.EncodeToString(h[:]) {
		t.Fatal("legacy block_source ownership changed")
	}
}

func TestActionAuthorityAndRecovery(t *testing.T) {
	cfg := actionConfig()
	cfg.StateFile = t.TempDir() + "/state"
	backend := NewDryRunBackend()
	c, err := New(cfg, backend)
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().UTC().Add(30 * time.Second)
	a := Action{Kind: Quarantine, Profile: "isolate"}
	l, err := c.CreateActionUntil(context.Background(), "quarantine", "192.0.2.1", deadline, a)
	if err != nil {
		t.Fatal(err)
	}
	// Mutating bootstrap caller storage must not change the admitted profile.
	p := cfg.Profiles["isolate"]
	p.Services[0].Port = 22
	cfg.Profiles["isolate"] = p
	for _, bad := range []Action{{Kind: Quarantine, Profile: "unknown"}, {Kind: "terminate_flow"}, {Kind: "request_rate"}, {Kind: BlockSource, Profile: "isolate"}, {Kind: DropFlow, Flow: Flow{Destination: "198.51.100.1", Protocol: "tcp", SourcePort: 3, DestinationPort: 443}}} {
		if _, err = c.CreateActionUntil(context.Background(), "bad", "192.0.2.2", deadline, bad); err == nil {
			t.Fatalf("accepted %+v", bad)
		}
	}
	if _, err = c.CreateActionUntil(context.Background(), l.ID, l.Source, deadline.Add(time.Second), a); err == nil {
		t.Fatal("renewed deadline")
	}
	if err = c.Close(); err != nil {
		t.Fatal(err)
	}
	cfg = actionConfig()
	cfg.StateFile = c.config.StateFile
	c, err = New(cfg, backend)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	ls, err := c.List(context.Background())
	if err != nil || len(ls) != 1 || ls[0] != l {
		t.Fatalf("recovery changed action/deadline: %+v %v", ls, err)
	}
}

func TestProtectedManagementAndProfileValidation(t *testing.T) {
	for _, mutate := range []func(*Config){
		func(c *Config) { c.Profiles["isolate"] = Profile{Kind: Quarantine, Services: []Service{{"tcp", 22}}} },
		func(c *Config) {
			c.Profiles["packets"] = Profile{Kind: RateSource, Services: []Service{{"udp", 53}}, Unit: "requests", Rate: 1, Burst: 2}
		},
		func(c *Config) {
			c.Profiles["redirect"] = Profile{Kind: RedirectSource, Services: []Service{{"tcp", 443}}, Destination: "https://evil", Port: 80}
		},
	} {
		cfg := actionConfig()
		mutate(&cfg)
		if c, err := New(cfg, NewDryRunBackend()); err == nil {
			c.Close()
			t.Fatal("accepted invalid bootstrap")
		}
	}
}

func TestTypedHTTPStrictnessAndCapabilities(t *testing.T) {
	c, err := New(actionConfig(), NewDryRunBackend())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	h := c.Handler()
	for _, body := range []string{
		`{"id":"bad","source":"192.0.2.1","ttl_seconds":10,"action":{"kind":"quarantine","profile":"isolate","url":"https://evil"}}`,
		`{"id":"bad","source":"192.0.2.1","ttl_seconds":10,"action":{"kind":"drop_flow","flow":{"destination":"10.0.0.1","protocol":"tcp","source_port":2,"source_port":3,"destination_port":443}}}`,
	} {
		r := httptest.NewRequest(http.MethodPost, "/v1/leases", strings.NewReader(body))
		r.Header.Set("Authorization", "Bearer "+c.config.Token)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 400 {
			t.Fatalf("accepted ambiguous or arbitrary action: %d %s", w.Code, w.Body.String())
		}
	}
	r := httptest.NewRequest(http.MethodGet, "/v1/capabilities", nil)
	r.Header.Set("Authorization", "Bearer "+c.config.Token)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	var capabilities enforcerCapabilities
	if err := json.Unmarshal(w.Body.Bytes(), &capabilities); err != nil || !capabilities.PacketFlow || capabilities.ApplicationReject || capabilities.ProactiveTermination || capabilities.RequestRate {
		t.Fatalf("capabilities: %s %v", w.Body.String(), err)
	}
}

func TestTypedMCPStaticAuthorizationAndSchema(t *testing.T) {
	c, err := New(actionConfig(), NewDryRunBackend())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	h := c.Handler()
	call := func(raw, token string) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(raw))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Accept", "application/json, text/event-stream")
		if token != "" {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	list := `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`
	create := `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"create_action_lease","arguments":{"id":"q","source":"192.0.2.1","ttl_seconds":10,"action":{"kind":"quarantine","profile":"isolate"}}}}`
	for _, raw := range []string{list, create, `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"revoke_action_lease","arguments":{"id":"q"}}}`} {
		for _, token := range []string{"", strings.Repeat("wrong", 8)} {
			if w := call(raw, token); w.Code != 401 {
				t.Fatalf("MCP bypassed bearer boundary: %d %s", w.Code, w.Body.String())
			}
		}
	}
	ls, _ := c.List(t.Context())
	if len(ls) != 0 {
		t.Fatal("unauthorized mutation")
	}
	w := call(list, c.config.Token)
	var response struct {
		Result struct {
			Tools []struct {
				Name        string `json:"name"`
				InputSchema struct {
					Properties map[string]json.RawMessage `json:"properties"`
				} `json:"inputSchema"`
			} `json:"tools"`
		} `json:"result"`
	}
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &response) != nil {
		t.Fatal(w.Body.String())
	}
	found := false
	for _, tool := range response.Result.Tools {
		if tool.Name != "create_action_lease" {
			continue
		}
		var schema struct {
			Properties struct {
				Kind struct {
					Enum []string `json:"enum"`
				} `json:"kind"`
			} `json:"properties"`
		}
		if json.Unmarshal(tool.InputSchema.Properties["action"], &schema) != nil {
			t.Fatal("missing typed schema")
		}
		got, _ := json.Marshal(schema.Properties.Kind.Enum)
		want, _ := json.Marshal(c.actionKinds())
		if string(got) != string(want) {
			t.Fatalf("advertised enum %s != backend %s", got, want)
		}
		found = true
	}
	if !found {
		t.Fatal("missing create tool")
	}
	if w = call(create, c.config.Token); w.Code != 200 || strings.Contains(w.Body.String(), `"isError":true`) {
		t.Fatal(w.Body.String())
	}
	ls, err = c.List(t.Context())
	if err != nil || len(ls) != 1 || ls[0].Action.Kind != Quarantine {
		t.Fatalf("typed MCP lease: %+v %v", ls, err)
	}
}
