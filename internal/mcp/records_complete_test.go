package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	mcplib "github.com/mark3labs/mcp-go/mcp"
)

func TestOversizedAuditRecordHasCompleteArtifact(t *testing.T) {
	record, _ := json.Marshal(map[string]any{"Method": "GET", "RequestHeader": map[string]string{"X-Large": strings.Repeat("value", 60000)}})
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("full") != "true" {
			t.Error("full structured records not requested")
		}
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprintf(w, "event: record\ndata: %s\n\nevent: complete\ndata: {\"total\":1,\"count\":1}\n\n", record)
	}))
	defer ts.Close()
	s, err := New(Options{BaseURL: ts.URL, CarveDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	res, err := s.handleQueryAuditRecords(context.Background(), mcplib.CallToolRequest{Params: mcplib.CallToolParams{Arguments: map[string]any{"session_id": "owned", "type": "HTTP"}}})
	if err != nil || res.IsError {
		t.Fatal(res, err)
	}
	var out struct {
		Records []struct {
			ID        string `json:"artifact_id"`
			Oversized bool   `json:"_oversized"`
		}
	}
	if err := json.Unmarshal([]byte(contentText(res)), &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Records) != 1 || !out.Records[0].Oversized {
		t.Fatal(contentText(res))
	}
	entry := s.carve.Get(out.Records[0].ID)
	if entry == nil || !bytes.Equal(entry.Bytes, record) || entry.MIMEType != "application/json" || entry.SessionID != "owned" {
		t.Fatal("complete structured artifact lost")
	}
	if contentSize(res) > MaxResponseBytes {
		t.Fatal("oversized response")
	}
}
