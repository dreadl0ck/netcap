//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/internal/testutil"
	"github.com/gopacket/gopacket/pcapgo"
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

func TestRecheck168SameNameCaptureIsolation(t *testing.T) {
	binary := os.Getenv("NETCAP_RECHECK168_BIN")
	if binary == "" {
		t.Skip("set NETCAP_RECHECK168_BIN to a built CLI")
	}
	root := t.TempDir()
	cli, err := client.NewStdioMCPClient(binary, os.Environ(), "mcp", "--quiet", "--bind", "127.0.0.1:0", "--data-dir", filepath.Join(root, "sessions"))
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()
	if stderr, ok := client.GetStderr(cli); ok {
		go io.Copy(io.Discard, stderr)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	if _, err := cli.Initialize(ctx, mcplib.InitializeRequest{Params: mcplib.InitializeParams{ProtocolVersion: "2025-11-25", ClientInfo: mcplib.Implementation{Name: "recheck168-isolation", Version: "1"}}}); err != nil {
		t.Fatal(err)
	}
	call := func(name string, args map[string]any, out any) {
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
		if err := json.Unmarshal([]byte(body.String()), out); err != nil {
			t.Fatal(name, err, body.String())
		}
	}
	ids := []string{}
	for _, fixture := range []string{"base_http.pcap", "http_pipelined.pcap", "base_http.pcap"} {
		data, err := os.ReadFile(testutil.Recheck168Capture(t, fixture))
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(t.TempDir(), "x.pcap")
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		var session struct {
			ID string `json:"session_id"`
		}
		call("ingest_pcap", map[string]any{"path": path}, &session)
		if session.ID == "" || strings.ContainsAny(session.ID, "/\\") {
			t.Fatal("expected opaque analysis ID", session.ID)
		}
		for _, prior := range ids {
			if prior == session.ID {
				t.Fatal("analysis ID reused")
			}
		}
		ids = append(ids, session.ID)
		var state struct{ Completed bool }
		call("wait_for_session", map[string]any{"session_id": session.ID, "timeout_seconds": 20, "poll_interval_ms": 100}, &state)
		if !state.Completed {
			t.Fatal("capture did not complete")
		}
		var timeline struct{ Status, Generation string }
		call("get_timeline_meta", map[string]any{"session_id": session.ID}, &timeline)
		if timeline.Status != "ready" || timeline.Generation == "" {
			t.Fatalf("completed session timeline was not ready: %+v", timeline)
		}
		for i, id := range ids {
			var records struct{ Summary struct{ Total int } }
			call("query_audit_records", map[string]any{"session_id": id, "type": "HTTP", "count_only": true, "limit": 10}, &records)
			want := 1
			if i == 1 {
				want = 3
			}
			if records.Summary.Total != want {
				t.Fatalf("session %d returned another capture: got %d HTTP records, want %d", i, records.Summary.Total, want)
			}
		}
	}
	var httpRecords struct {
		Records []struct {
			SrcIP, DstIP     string
			SrcPort, DstPort int
		}
	}
	call("query_audit_records", map[string]any{"session_id": ids[0], "type": "HTTP", "limit": 1}, &httpRecords)
	if len(httpRecords.Records) != 1 || httpRecords.Records[0].SrcIP == "" {
		t.Fatal("missing HTTP tuple control", httpRecords)
	}
	tuple := httpRecords.Records[0]
	var priorCarve []byte
	for _, name := range []string{"carve_subpcap_for_http_pair", "carve_subpcap_for_certificate"} {
		var carved struct {
			Path string `json:"file_path"`
			Size int    `json:"size_bytes"`
		}
		call(name, map[string]any{"session_id": ids[0], "src_ip": tuple.SrcIP, "dst_ip": tuple.DstIP, "src_port": strconv.Itoa(tuple.SrcPort), "dst_port": strconv.Itoa(tuple.DstPort)}, &carved)
		raw, err := os.ReadFile(carved.Path)
		if err != nil || len(raw) != carved.Size {
			t.Fatal("incomplete carve", name, err)
		}
		reader, err := pcapgo.NewReader(bytes.NewReader(raw))
		if err != nil {
			t.Fatal(name, err)
		}
		if _, _, err := reader.ReadPacketData(); err != nil {
			t.Fatal(name, "empty or invalid carve", err)
		}
		if priorCarve != nil && !bytes.Equal(raw, priorCarve) {
			t.Fatal("same tuple produced different packet exports")
		}
		priorCarve = raw
	}
	var beforeDevices map[string]any
	call("list_devices", map[string]any{"session_id": ids[0]}, &beforeDevices)
	if count, ok := beforeDevices["totalCount"].(float64); !ok || count == 0 {
		t.Fatal("device isolation requires a nonempty control", beforeDevices)
	}
	var credentialSession struct {
		ID string `json:"session_id"`
	}
	call("ingest_pcap", map[string]any{"path": testutil.Recheck168Capture(t, "hv_std_userpass.pcap")}, &credentialSession)
	var credentialState struct{ Completed bool }
	call("wait_for_session", map[string]any{"session_id": credentialSession.ID, "timeout_seconds": 20, "poll_interval_ms": 100}, &credentialState)
	if !credentialState.Completed {
		t.Fatal("credential capture did not complete")
	}
	for _, tc := range []struct {
		id   string
		want int
	}{{ids[0], 0}, {credentialSession.ID, 1}, {ids[0], 0}} {
		var secrets struct{ TotalCount int }
		call("list_secrets", map[string]any{"session_id": tc.id}, &secrets)
		if secrets.TotalCount != tc.want {
			t.Fatalf("cross-session secrets: got %d want %d", secrets.TotalCount, tc.want)
		}
	}
	var afterDevices map[string]any
	call("list_devices", map[string]any{"session_id": ids[0]}, &afterDevices)
	before, _ := json.Marshal(beforeDevices)
	after, _ := json.Marshal(afterDevices)
	if string(before) != string(after) {
		t.Fatalf("cross-session devices: before %s after %s", before, after)
	}
	var failedSession struct {
		ID string `json:"session_id"`
	}
	call("ingest_pcap", map[string]any{"path": testutil.Recheck168Capture(t, "ng_shb_trailer_mismatch.pcapng")}, &failedSession)
	for _, name := range []string{"wait_for_session", "get_session_info", "list_hosts", "list_secrets", "list_devices", "list_audit_records", "query_audit_records"} {
		args := map[string]any{"session_id": failedSession.ID}
		if name == "wait_for_session" {
			args["timeout_seconds"] = 20
			args["poll_interval_ms"] = 100
		}
		if name == "query_audit_records" {
			args["type"] = "HTTP"
		}
		result, err := cli.CallTool(ctx, mcplib.CallToolRequest{Params: mcplib.CallToolParams{Name: name, Arguments: args}})
		if err != nil {
			t.Fatal(name, err)
		}
		if !result.IsError {
			t.Fatalf("%s returned empty success for a failed capture: %+v", name, result)
		}
	}
	var largeSession struct {
		ID string `json:"session_id"`
	}
	call("ingest_pcap", map[string]any{"path": testutil.Recheck168Capture(t, "v168_udp_uniqflows_10k.pcap")}, &largeSession)
	var largeState struct{ Completed bool }
	call("wait_for_session", map[string]any{"session_id": largeSession.ID, "timeout_seconds": 20, "poll_interval_ms": 100}, &largeState)
	if !largeState.Completed {
		t.Fatal("large count control did not complete")
	}
	var counts struct {
		Returned int
		Records  json.RawMessage
		Summary  struct{ Total, Count int }
	}
	call("query_audit_records", map[string]any{"session_id": largeSession.ID, "type": "Connection", "count_only": true, "limit": 1}, &counts)
	if counts.Returned != 0 || counts.Records != nil || counts.Summary.Count != 0 || counts.Summary.Total != 10000 {
		t.Fatalf("large count-only result was capped or transferred records: %+v", counts)
	}
}
