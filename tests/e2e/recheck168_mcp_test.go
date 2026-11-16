//go:build e2e

package e2e

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/internal/testutil"
	"github.com/mark3labs/mcp-go/client"
	mcplib "github.com/mark3labs/mcp-go/mcp"
)

func TestRecheck168PackagedMCPHelperIdentity(t *testing.T) {
	binary := os.Getenv("NETCAP_RECHECK168_BIN")
	if binary == "" {
		t.Skip("set NETCAP_RECHECK168_BIN to a built CLI; optional NETCAP_RECHECK168_LOADER exercises the shipped loader layout")
	}
	for _, shadow := range []bool{false, true} {
		t.Run(map[bool]string{false: "empty-path", true: "shadow-path"}[shadow], func(t *testing.T) {
			root := t.TempDir()
			marker := filepath.Join(root, "wrong-helper-ran")
			if shadow {
				body := "#!/bin/sh\n: > \"" + marker + "\"\nexit 99\n"
				if err := os.WriteFile(filepath.Join(root, "net"), []byte(body), 0700); err != nil {
					t.Fatal(err)
				}
			}
			command := binary
			args := []string{}
			if loader := os.Getenv("NETCAP_RECHECK168_LOADER"); loader != "" {
				command = loader
				args = []string{"--library-path", filepath.Dir(loader), binary}
			}
			args = append(args, "mcp", "--quiet", "--bind", "127.0.0.1:0", "--data-dir", filepath.Join(root, "sessions"))
			env := append(os.Environ(), "PATH="+root)
			cli, err := client.NewStdioMCPClient(command, env, args...)
			if err != nil {
				t.Fatal(err)
			}
			defer cli.Close()
			if stderr, ok := client.GetStderr(cli); ok {
				go io.Copy(io.Discard, stderr)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			if _, err := cli.Initialize(ctx, mcplib.InitializeRequest{Params: mcplib.InitializeParams{ProtocolVersion: "2025-11-25", ClientInfo: mcplib.Implementation{Name: "recheck168-helper", Version: "1"}}}); err != nil {
				t.Fatal(err)
			}
			call := func(name string, args map[string]any) string {
				t.Helper()
				result, err := cli.CallTool(ctx, mcplib.CallToolRequest{Params: mcplib.CallToolParams{Name: name, Arguments: args}})
				if err != nil {
					t.Fatal(err)
				}
				var body strings.Builder
				for _, content := range result.Content {
					if text, ok := content.(mcplib.TextContent); ok {
						body.WriteString(text.Text)
					}
				}
				if result.IsError {
					t.Fatal(name, body.String())
				}
				return body.String()
			}
			var session struct {
				ID string `json:"session_id"`
			}
			if err := json.Unmarshal([]byte(call("ingest_pcap", map[string]any{"path": testutil.Recheck168Capture(t, "base_http.pcap")})), &session); err != nil || session.ID == "" {
				t.Fatal("ingest session", err)
			}
			completion := call("wait_for_session", map[string]any{"session_id": session.ID, "timeout_seconds": 20, "poll_interval_ms": 100})
			var state struct {
				Completed bool
				Error     any
				Status    string
			}
			if err := json.Unmarshal([]byte(completion), &state); err != nil || !state.Completed || state.Error != nil || state.Status == "failed" {
				t.Fatal(completion, err)
			}
			records := call("query_audit_records", map[string]any{"session_id": session.ID, "type": "HTTP", "count_only": true, "limit": 10})
			if !strings.Contains(records, `"total": 1`) && !strings.Contains(records, `"total":1`) {
				t.Fatal("matching helper did not produce supplied HTTP record", records)
			}
			if _, err := os.Stat(marker); !os.IsNotExist(err) {
				t.Fatal("PATH helper executed")
			}
		})
	}
}
