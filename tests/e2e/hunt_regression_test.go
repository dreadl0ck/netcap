//go:build e2e

package e2e

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mark3labs/mcp-go/client"
	mcplib "github.com/mark3labs/mcp-go/mcp"
)

func TestHuntCLIRegressions(t *testing.T) {
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	temp := t.TempDir()
	binary := filepath.Join(temp, "net")
	tags := os.Getenv("NETCAP_HUNT_BUILD_TAGS")
	if tags == "" {
		tags = "nodpi,noyara,nomagika"
	}
	const buildCommit = "0123456789abcdef0123456789abcdef01234567"
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	build := exec.CommandContext(ctx, "go", "build", "-tags="+tags, "-ldflags=-X github.com/dreadl0ck/netcap.Commit="+buildCommit, "-o", binary, "./cmd/net")
	build.Dir = root
	build.Env = append(os.Environ(), "GOWORK=off")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, output)
	}
	input := filepath.Join(temp, "input.pcap")
	writeTestPCAP(t, input, 0)
	env := append(os.Environ(), "NC_CONFIG_ROOT="+filepath.Join(temp, "config"))
	run := func(args ...string) ([]byte, error) {
		cmd := exec.CommandContext(ctx, binary, args...)
		cmd.Dir = temp
		cmd.Env = env
		return cmd.CombinedOutput()
	}
	if output, err := run("--version"); err != nil || !strings.Contains(string(output), buildCommit) {
		t.Fatalf("release build commit missing: %v\n%s", err, output)
	}
	help, err := run("capture", "--help")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(help), "--gen-config") || strings.Contains(string(help), "default is unbuffered") {
		t.Fatal("help advertises unsupported or contradictory behavior")
	}
	for _, line := range strings.Split(string(help), "\n") {
		if strings.Count(line, "(default:") > 1 {
			t.Fatalf("contradictory help defaults: %s", line)
		}
	}
	listing, err := run("capture", "--decoders", "--quiet")
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]int{}
	for _, line := range strings.Split(string(listing), "\n") {
		fields := strings.Fields(line)
		if len(fields) > 2 && fields[0] == "+" && fields[2] == "(" {
			names[fields[1]]++
		}
	}
	for _, name := range []string{"DNS", "SIP", "MQTTSN", "TLSCertificate", "Zabbix", "CIP", "Protobuf", "USB", "USBRequestBlockSetup"} {
		if names[name] != 1 {
			t.Fatalf("decoder %s listed %d times", name, names[name])
		}
	}
	out := filepath.Join(temp, "audit")
	capture := []string{"capture", "--read", input, "--out", out, "--include", " dns, connection, host ", "--http", "", "--quiet", "-y", "--geoDB=false", "--fileStorage", ""}
	var firstID string
	if err := os.MkdirAll(out, 0700); err != nil {
		t.Fatal(err)
	}
	notes := []byte("operator-owned CSV; not an audit record\n")
	if err := os.WriteFile(filepath.Join(out, "notes.csv"), notes, 0600); err != nil {
		t.Fatal(err)
	}
	for i := range 2 {
		if output, err := run(capture...); err != nil {
			t.Fatalf("overwrite run %d: %v\n%s", i, err, output)
		}
		data, err := os.ReadFile(filepath.Join(out, "capture-manifest.json"))
		if err != nil {
			t.Fatal(err)
		}
		var manifest struct {
			RunID    string `json:"runId"`
			Status   string `json:"status"`
			Producer struct {
				Commit string `json:"commit"`
			} `json:"producer"`
		}
		if err := json.Unmarshal(data, &manifest); err != nil || manifest.Status != "done" || manifest.RunID == "" || manifest.RunID == firstID {
			t.Fatalf("run identity/status: %s %v", data, err)
		}
		firstID = manifest.RunID
		if manifest.Producer.Commit != buildCommit {
			t.Fatal("capture producer lost build commit", manifest.Producer.Commit)
		}
	}
	if data, err := os.ReadFile(filepath.Join(out, "notes.csv")); err != nil || !bytes.Equal(data, notes) {
		t.Fatal("overwrite removed unrelated operator data", err)
	}
	old, err := os.ReadFile(filepath.Join(out, "DNS.ncap.gz"))
	if err != nil {
		t.Fatal(err)
	}
	wantHash := sha256.Sum256(old)
	for _, extra := range [][]string{{"--include", "Bogus"}, {"--flow-export-ports", "invalid"}} {
		args := append(append([]string{}, capture...), extra...)
		if output, err := run(args...); err == nil {
			t.Fatalf("invalid startup succeeded: %s", output)
		}
		data, err := os.ReadFile(filepath.Join(out, "DNS.ncap.gz"))
		if err != nil || sha256.Sum256(data) != wantHash {
			t.Fatal("startup failure destroyed previous audit", err)
		}
	}
	for _, tc := range []struct {
		args      []string
		wantError bool
		contains  string
	}{
		{[]string{"dump", "--read", filepath.Join(out, "DNS.ncap.gz"), "--filter", "ID = 1"}, true, "compile audit filter"},
		{[]string{"dump", "--read", filepath.Join(out, "DNS.ncap.gz"), "--select", "Bogus"}, true, "invalid field"},
		{[]string{"util", "--ts2utc", "1600000000.5"}, false, "2020-09-13 12:26:40.5"},
		{[]string{"util", "--ts2utc", "garbage"}, true, "invalid timestamp"},
		{[]string{"capture", "--read", input, "--out", filepath.Join(temp, "unexpected"), "--bpf", "udp", "port", "9999"}, true, "quote the entire --bpf"},
	} {
		output, err := run(tc.args...)
		if (err != nil) != tc.wantError || !strings.Contains(string(output), tc.contains) || strings.Contains(string(output), "\x1b[") {
			t.Fatalf("%v: %v\n%s", tc.args, err, output)
		}
	}
	for _, command := range []string{"capture", "dump", "util", "proxy", "label", "export"} {
		output, err := run(command, "--gen-config")
		if err == nil || !strings.Contains(string(output), "not implemented") {
			t.Fatalf("%s: %v %s", command, err, output)
		}
	}
	output, err := run("dump", "--read", filepath.Join(out, "DNS.ncap.gz"), "--json", "--select", "ID,QR")
	if err != nil {
		t.Fatalf("JSON selection: %v\n%s", err, output)
	}
	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	if len(lines) != 3 {
		t.Fatalf("expected three projected DNS records: %s", output)
	}
	for _, line := range lines {
		var row map[string]any
		if err := json.Unmarshal([]byte(line), &row); err != nil || len(row) != 2 || row["ID"] != float64(1) || row["QR"] != false {
			t.Fatalf("projection: %s %v", line, err)
		}
	}
	csvOut := filepath.Join(temp, "csv")
	args := append(append([]string{}, capture...), "--out", csvOut, "--csv")
	if output, err := run(args...); err != nil {
		t.Fatalf("CSV: %v\n%s", err, output)
	}
	paths, err := filepath.Glob(filepath.Join(csvOut, "*.csv.gz"))
	if err != nil || len(paths) < 3 {
		t.Fatal("missing compressed CSV outputs", paths, err)
	}
	for _, path := range paths {
		f, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		gz, err := gzip.NewReader(f)
		if err != nil {
			f.Close()
			t.Fatal(err)
		}
		rows, err := csv.NewReader(gz).ReadAll()
		gz.Close()
		f.Close()
		if err != nil || len(rows) < 2 {
			t.Fatalf("corrupt CSV %s: rows=%d %v", path, len(rows), err)
		}
	}
	if !strings.Contains(tags, "nodpi") {
		args := append(append([]string{}, capture...), "--out", filepath.Join(temp, "dpi"), "--dpi")
		if output, err := run(args...); err != nil || strings.Contains(string(output), "[DPI]") || strings.Contains(string(output), "\x1b[") {
			t.Fatalf("quiet DPI capture: %v\n%s", err, output)
		}
	}
	t.Run("MCP real ingest", func(t *testing.T) {
		cli, err := client.NewStdioMCPClient(binary, env, "mcp", "--bind", "127.0.0.1:0", "--data-dir", filepath.Join(temp, "mcp"), "--quiet")
		if err != nil {
			t.Fatal(err)
		}
		defer cli.Close()
		if stderr, ok := client.GetStderr(cli); ok {
			go io.Copy(io.Discard, stderr)
		}
		if _, err := cli.Initialize(ctx, mcplib.InitializeRequest{Params: mcplib.InitializeParams{ProtocolVersion: "2024-11-05", ClientInfo: mcplib.Implementation{Name: "hunt-regression", Version: "1"}}}); err != nil {
			t.Fatal(err)
		}
		call := func(name string, args map[string]any) string {
			t.Helper()
			result, err := cli.CallTool(ctx, mcplib.CallToolRequest{Params: mcplib.CallToolParams{Name: name, Arguments: args}})
			if err != nil {
				t.Fatal(name, err)
			}
			var body strings.Builder
			for _, content := range result.Content {
				if text, ok := content.(mcplib.TextContent); ok {
					body.WriteString(text.Text)
				}
			}
			if result.IsError {
				t.Fatalf("%s: %s", name, body.String())
			}
			return body.String()
		}
		ingested := call("ingest_pcap", map[string]any{"path": input})
		var session struct {
			ID string `json:"session_id"`
		}
		if err := json.Unmarshal([]byte(ingested), &session); err != nil || session.ID == "" {
			t.Fatalf("ingest: %s %v", ingested, err)
		}
		completed := call("wait_for_session", map[string]any{"session_id": session.ID, "timeout_seconds": 30, "poll_interval_ms": 100})
		var state map[string]any
		if err := json.Unmarshal([]byte(completed), &state); err != nil || state["completed"] != true || state["error"] != nil || state["status"] == "failed" {
			t.Fatalf("analysis failed: %s %v", completed, err)
		}
		for _, name := range []string{"list_hosts", "list_connections"} {
			result := call(name, map[string]any{"session_id": session.ID})
			if !strings.Contains(result, "192.0.2.1") {
				t.Fatalf("%s missing host/connection records: %s", name, result)
			}
		}
		t.Log(fmt.Sprintf("MCP ingested %s and retained Host/Connection records without DPI", filepath.Base(input)))
	})
}
