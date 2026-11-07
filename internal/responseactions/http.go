package responseactions

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"time"

	"github.com/dreadl0ck/netcap/internal/enforcer"
	"github.com/dreadl0ck/netcap/internal/policy"
)

func (b *Broker) deliver(i policy.Intent) (string, string) {
	ctx, cancel := context.WithDeadline(b.ctx, i.ExpiresAt)
	defer cancel()
	d := b.scopes[i.Scope]
	if ctx.Err() != nil {
		return "failed", "expired-or-closed"
	}
	if reason := b.verifyScope(ctx, d, i.TTL); reason != "" {
		return "failed", reason
	}
	for attempt := 0; attempt < 3; attempt++ {
		if ctx.Err() != nil {
			return "failed", "expired-or-closed"
		}
		// Recover uncertain POST outcomes by ID before retrying. Never replace or
		// extend an existing lease, even when the preceding response was lost.
		if attempt > 0 {
			var leases []enforcer.Lease
			code, ok := b.request(ctx, d, http.MethodGet, nil, &leases)
			if code == http.StatusOK && ok {
				for _, l := range leases {
					if l.ID == i.ID {
						if validLease(l, i, d) {
							return "applied", "recovered"
						}
						return "failed", "lease-mismatch"
					}
				}
			} else {
				continue
			}
		}
		if time.Until(i.ExpiresAt) < time.Millisecond {
			return "failed", "expired"
		}
		body, _ := json.Marshal(struct {
			ID        string    `json:"id"`
			Source    string    `json:"source"`
			TTL       int64     `json:"ttl_seconds"`
			ExpiresAt time.Time `json:"expires_at"`
		}{i.ID, i.Source, int64(i.TTL / time.Second), i.ExpiresAt})
		var lease enforcer.Lease
		code, ok := b.request(ctx, d, http.MethodPost, body, &lease)
		if code == http.StatusCreated && ok {
			if !validLease(lease, i, d) {
				return "failed", "lease-mismatch"
			}
			return "applied", ""
		}
		if code >= 400 && code < 500 && code != 429 {
			return "failed", "enforcer-rejected"
		}
		timer := time.NewTimer(time.Duration(attempt+1) * 100 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return "failed", "expired-or-closed"
		case <-timer.C:
		}
	}
	return "failed", "delivery-exhausted"
}

func validLease(l enforcer.Lease, i policy.Intent, d destination) bool {
	return l.ID == i.ID && l.Source == i.Source && l.Scope == d.network && l.TTLSeconds > 0 && l.TTLSeconds <= int64(i.TTL/time.Second) && l.ExpiresAt.After(time.Now()) && l.ExpiresAt.Equal(i.ExpiresAt)
}

func (b *Broker) request(ctx context.Context, d destination, method string, body []byte, out any) (int, bool) {
	return b.requestPath(ctx, d, method, "/v1/leases", body, out)
}

func (b *Broker) requestPath(ctx context.Context, d destination, method, path string, body []byte, out any) (int, bool) {
	r, err := http.NewRequestWithContext(ctx, method, d.endpoint+path, bytes.NewReader(body))
	if err != nil {
		return 0, false
	}
	r.Header.Set("Authorization", "Bearer "+d.token)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Accept", "application/json, text/event-stream")
	response, err := b.client.Do(r)
	if err != nil {
		return 0, false
	}
	defer response.Body.Close()
	// The enforcer caps leases at 1000. Bound both reads and JSON allocation.
	raw, err := io.ReadAll(io.LimitReader(response.Body, (1<<20)+1))
	if err != nil || len(raw) > 1<<20 {
		return response.StatusCode, false
	}
	if response.StatusCode != http.StatusOK && response.StatusCode != http.StatusCreated {
		return response.StatusCode, false
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if decoder.Decode(out) != nil {
		return response.StatusCode, false
	}
	var extra any
	return response.StatusCode, decoder.Decode(&extra) == io.EOF
}

// The existing enforcer exposes immutable scope through its authenticated MCP
// capability tool. Verify before mutation; a lease response is too late to check.
func (b *Broker) verifyScope(ctx context.Context, d destination, ttl time.Duration) string {
	body := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_enforcer_capabilities","arguments":{}}}`)
	var response struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      int             `json:"id"`
		Error   json.RawMessage `json:"error"`
		Result  struct {
			IsError bool `json:"isError"`
			Content []struct {
				Type string `json:"type"`
				Text string `json:"text"`
			} `json:"content"`
		} `json:"result"`
	}
	code, ok := b.requestPath(ctx, d, http.MethodPost, "/mcp", body, &response)
	if code != http.StatusOK || !ok || response.JSONRPC != "2.0" || response.ID != 1 || (len(response.Error) > 0 && string(response.Error) != "null") || response.Result.IsError || len(response.Result.Content) != 1 || response.Result.Content[0].Type != "text" {
		return "capabilities-unavailable"
	}
	var capabilities struct {
		Scope             *enforcer.Scope `json:"scope"`
		ScopeMutable      *bool           `json:"scope_mutable"`
		GenericCommands   *bool           `json:"generic_commands"`
		Actions           []string        `json:"actions"`
		MaxTTL            int64           `json:"max_ttl_seconds"`
		MaxLeases         int             `json:"max_leases"`
		AbsoluteDeadlines bool            `json:"absolute_deadlines"`
	}
	if json.Unmarshal([]byte(response.Result.Content[0].Text), &capabilities) != nil || capabilities.Scope == nil || *capabilities.Scope != d.network || capabilities.ScopeMutable == nil || *capabilities.ScopeMutable || capabilities.GenericCommands == nil || *capabilities.GenericCommands || len(capabilities.Actions) != 1 || capabilities.Actions[0] != "block_source" {
		return "scope-mismatch"
	}
	if capabilities.MaxTTL < 1 || capabilities.MaxTTL > int64(policy.MaxEffectTTL/time.Second) || capabilities.MaxLeases < 1 || capabilities.MaxLeases > enforcer.HardMaxLeases || int64(ttl/time.Second) > capabilities.MaxTTL {
		return "capability-limits"
	}
	if !capabilities.AbsoluteDeadlines {
		return "absolute-deadlines-unavailable"
	}
	return ""
}
