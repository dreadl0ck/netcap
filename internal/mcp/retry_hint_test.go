package mcp

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	mcplib "github.com/mark3labs/mcp-go/mcp"
)

// Busy backends answer 429 with Retry-After; tools must surface a retry hint
// instead of a plain error. Size and storage failures are not retryable.
func TestBackendBusyIsRetryable(t *testing.T) {
	for _, tc := range []struct {
		status     int
		retryAfter string
		want       string
	}{
		{http.StatusTooManyRequests, "2", "; retry_after_ms=2000"},
		{http.StatusTooManyRequests, "", "; retry_after_ms=1000"},
		{http.StatusServiceUnavailable, "1", "; retry_after_ms=1000"},
		{http.StatusRequestEntityTooLarge, "", ""},
		{http.StatusInsufficientStorage, "", ""},
	} {
		backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if tc.retryAfter != "" {
				w.Header().Set("Retry-After", tc.retryAfter)
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(tc.status)
			w.Write([]byte(`{"error":"alert reads are busy"}`))
		}))
		s, err := New(Options{BaseURL: backend.URL})
		if err != nil {
			t.Fatal(err)
		}
		for name, args := range map[string]map[string]any{
			"list_alerts":          {"session_id": "owned"},
			"list_alerts_grouped":  {"session_id": "owned"},
			"get_alert_stats":      {"session_id": "owned"},
			"get_behavior_records": {"session_id": "owned", "alertId": "a"},
		} {
			tool := s.mcpSrv.GetTool(name)
			if tool == nil {
				t.Fatalf("%s not registered", name)
			}
			result, err := tool.Handler(t.Context(), mcplib.CallToolRequest{Params: mcplib.CallToolParams{Name: name, Arguments: args}})
			text := contentText(result)
			if err != nil || !result.IsError {
				t.Fatalf("%s %d: %v %s", name, tc.status, err, text)
			}
			hinted := strings.Contains(text, "retry_after_ms=")
			if tc.want == "" && hinted || tc.want != "" && !strings.HasSuffix(text, tc.want) {
				t.Errorf("%s %d: %q, want suffix %q", name, tc.status, text, tc.want)
			}
		}
		backend.Close()
	}
}
