package mcp

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	mcplib "github.com/mark3labs/mcp-go/mcp"
)

func TestLargeEvidenceAndSessionInfoRemainInspectable(t *testing.T) {
	manifest, _ := json.Marshal(map[string]any{"runId": "run", "inputSHA256": "source-hash", "interfaces": []string{strings.Repeat("large", 100000)}})
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/files/input":
			io.WriteString(w, `[{"path":"/owned.pcap","isCompleted":true}]`)
		case "/api/audit-stats":
			io.WriteString(w, `{}`)
		case "/api/investigation/capture":
			w.Write(manifest)
		default:
			t.Error("unexpected/global metadata request", r.URL)
			w.WriteHeader(404)
		}
	}))
	defer ts.Close()
	s, err := New(Options{BaseURL: ts.URL, CarveDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	req := mcplib.CallToolRequest{Params: mcplib.CallToolParams{Arguments: map[string]any{"session_id": "/owned.pcap"}}}
	info, err := s.handleGetSessionInfo(context.Background(), req)
	if err != nil || info.IsError || contentSize(info) > 8192 || !strings.Contains(contentText(info), "source-hash") {
		t.Fatal(contentText(info), err)
	}
	full, err := s.mcpSrv.GetTool("get_capture_evidence").Handler(context.Background(), req)
	if err != nil || full.IsError {
		t.Fatal(full, err)
	}
	var ref struct {
		ID string `json:"artifact_id"`
	}
	if err := json.Unmarshal([]byte(contentText(full)), &ref); err != nil {
		t.Fatal(err)
	}
	entry := s.carve.Get(ref.ID)
	if entry == nil || string(entry.Bytes) != string(manifest) {
		t.Fatal("complete evidence artifact missing")
	}
}
