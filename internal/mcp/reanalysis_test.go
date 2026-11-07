package mcp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	mcplib "github.com/mark3labs/mcp-go/mcp"
)

func TestReanalysisForwardsQualifiedSubsetAndReturnsChild(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/status" {
			w.Write([]byte(`{"childAnalysisVersion":1}`))
			return
		}
		if r.URL.Path != "/api/reanalyze" || r.Method != "POST" {
			t.Errorf("unexpected backend request: %s %s", r.Method, r.URL)
			w.WriteHeader(404)
			return
		}
		var body struct {
			InputFile string `json:"inputFile"`
			RunID     string `json:"runId"`
			Selection struct {
				Version      int    `json:"version"`
				SourceSHA256 string `json:"sourceSHA256"`
				BPF          string `json:"bpf"`
				StartNs      string `json:"startNs"`
				EndNs        string `json:"endNs"`
			} `json:"selection"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		if body.InputFile != "/owned.pcap" || body.RunID != "parent-run" || body.Selection.Version != 1 || body.Selection.SourceSHA256 != "parent-hash" || body.Selection.BPF != "tcp port 9243" || body.Selection.StartNs != "1700000000000000001" || body.Selection.EndNs != "1700000000000000002" {
			t.Errorf("lost source selection: %+v", body)
		}
		w.Write([]byte(`{"success":true,"sessionId":"analysis-child","path":"/analysis-child/source/selected.pcapng"}`))
	}))
	defer backend.Close()
	s, err := New(Options{BaseURL: backend.URL, CarveDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	result, err := s.handleReanalyzeSession(context.Background(), mcplib.CallToolRequest{Params: mcplib.CallToolParams{Arguments: map[string]any{
		"session_id": "/owned.pcap", "run_id": "parent-run", "source_sha256": "parent-hash", "selection_bpf": "tcp port 9243", "start_ns": "1700000000000000001", "end_ns": "1700000000000000002",
	}}})
	if err != nil || result.IsError {
		t.Fatalf("result=%s err=%v", contentText(result), err)
	}
	var returned struct {
		SessionID string `json:"sessionId"`
	}
	if json.Unmarshal([]byte(contentText(result)), &returned) != nil || returned.SessionID != "analysis-child" {
		t.Fatal("parent identity returned instead of child")
	}
	ref := newSessionRef(returned.SessionID)
	files := json.RawMessage(`[{"id":"analysis-child","path":"/analysis-child/source/selected.pcapng","isCompleted":true}]`)
	if !deriveCompleted(ref, files, nil) {
		t.Fatal("local child ID cannot be polled")
	}
}

func TestReanalysisRefusesLegacyBackendBeforeMutation(t *testing.T) {
	posted := false
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			posted = true
		}
		w.Write([]byte(`{}`))
	}))
	defer backend.Close()
	s, err := New(Options{BaseURL: backend.URL, CarveDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	result, err := s.handleReanalyzeSession(context.Background(), mcplib.CallToolRequest{Params: mcplib.CallToolParams{Arguments: map[string]any{"session_id": "/owned.pcap"}}})
	if err != nil || !result.IsError || posted {
		t.Fatal("legacy backend was allowed to destructively reanalyze")
	}
}

func TestSessionInfoProvidesSourceBoundSubsetProvenance(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/status":
			w.Write([]byte(`{"activeInputFile":"/other.pcap","isProcessing":false}`))
		case "/api/files/input":
			w.Write([]byte(`[{"path":"/owned.pcap","isCompleted":true}]`))
		case "/api/audit-stats", "/api/investigation/capture":
			if r.URL.Query().Get("inputFile") != "/owned.pcap" || r.URL.Query().Get("scope") != "" {
				t.Errorf("conflicting capture selector: %s", r.URL)
			}
			if r.URL.Path == "/api/investigation/capture" {
				w.Write([]byte(`{"runId":"owned-generation","inputSHA256":"owned-hash"}`))
			} else {
				w.Write([]byte(`{}`))
			}
		default:
			t.Errorf("unexpected backend path: %s", r.URL.Path)
			w.WriteHeader(404)
		}
	}))
	defer backend.Close()
	s, err := New(Options{BaseURL: backend.URL, CarveDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	result, err := s.handleGetSessionInfo(context.Background(), mcplib.CallToolRequest{Params: mcplib.CallToolParams{Arguments: map[string]any{"session_id": "/owned.pcap"}}})
	if err != nil || result.IsError {
		t.Fatalf("result=%s err=%v", contentText(result), err)
	}
	var info struct {
		Capture struct {
			RunID       string `json:"runId"`
			InputSHA256 string `json:"inputSHA256"`
		} `json:"capture_provenance"`
	}
	if json.Unmarshal([]byte(contentText(result)), &info) != nil || info.Capture.RunID != "owned-generation" || info.Capture.InputSHA256 != "owned-hash" {
		t.Fatal("MCP cannot obtain the parent's subset binding")
	}
}
