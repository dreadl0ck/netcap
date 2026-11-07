package firewallaudit_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/cmd/capture"
	"github.com/dreadl0ck/netcap/internal/enforcer"
	"github.com/dreadl0ck/netcap/internal/firewallaudit"
	"github.com/dreadl0ck/netcap/internal/policy"
	"github.com/dreadl0ck/netcap/internal/responseactions"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
	"github.com/urfave/cli/v3"
)

func TestCaptureSchemaAndExplicitOptIn(t *testing.T) {
	var output bytes.Buffer
	c := &cli.Command{Flags: capture.GetFlags(), Action: capture.RunWithContext, Writer: &output, ErrWriter: &output}
	if err := c.Run(context.Background(), []string{"capture", "--firewall-schema"}); err != nil {
		t.Fatal(err)
	}
	var capabilities firewallaudit.Capabilities
	if err := json.Unmarshal(output.Bytes(), &capabilities); err != nil {
		t.Fatal(err)
	}
	if capabilities.Version != firewallaudit.Discover().Version || len(capabilities.Records) < 200 || capabilities.EvaluationPhase != "request" {
		t.Fatal("CLI schema mismatch")
	}
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"--firewall-effects-config", "missing"}, "requires firewall-policy"},
		{[]string{"--firewall-policy", "missing", "--service"}, "service/upload mode is unsupported"},
		{[]string{"--firewall-policy", "missing", "--iface", "lo0", "--read", "missing"}, "either -read or -iface"},
	} {
		c = &cli.Command{Flags: capture.GetFlags(), Action: capture.RunWithContext, Writer: &output, ErrWriter: &output}
		err := c.Run(context.Background(), append([]string{"capture"}, tc.args...))
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("%v: %v", tc.args, err)
		}
	}
}

func TestCaptureReplayProcess(t *testing.T) {
	encoded := os.Getenv("FIREWALL_AUDIT_REPLAY")
	if encoded == "" {
		return
	}
	var args []string
	if err := json.Unmarshal([]byte(encoded), &args); err != nil {
		t.Fatal(err)
	}
	f, err := os.Create(os.Getenv("FIREWALL_AUDIT_OUTPUT"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	c := &cli.Command{Flags: capture.GetFlags(), Action: capture.RunWithContext, Writer: io.Discard, ErrWriter: f}
	if err = c.Run(context.Background(), append([]string{"capture"}, args...)); err != nil {
		t.Fatal(err)
	}
}

func TestCaptureMultiFileReplayNeverContactsEnforcer(t *testing.T) {
	var calls atomic.Int32
	var connections atomic.Int32
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); w.WriteHeader(500) }))
	server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			connections.Add(1)
		}
	}
	server.StartTLS()
	defer server.Close()
	dir := t.TempDir()
	fixture, err := os.ReadFile(filepath.Join("..", "networkdetect", "testdata", "tunnel-dns.pcap"))
	if err != nil {
		t.Fatal(err)
	}
	pcap, err := pcapgo.NewReader(bytes.NewReader(fixture))
	if err != nil {
		t.Fatal(err)
	}
	expected := 0
	for {
		data, _, err := pcap.ReadPacketData()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.Default).Layer(layers.LayerTypeDNS) != nil {
			expected += 2
		}
	}
	for _, name := range []string{"one.pcap", "two.pcap"} {
		if err = os.WriteFile(filepath.Join(dir, name), fixture, 0600); err != nil {
			t.Fatal(err)
		}
	}
	b := policy.Bundle{Version: "1", ID: "capture-replay", Mode: "enforce", Default: "allow", Rules: []policy.Rule{{ID: "dns", Action: "deny", Expression: "Protocol == 'audit' && RecordType == 'DNS' && Fields['Questions[0].Name'] != ''", Effects: []policy.Effect{{Kind: "block_source", Target: "source", Duration: "30s", Scope: "edge"}}}}}
	write := func(name string, value any) string {
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(dir, name)
		if err = os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	policyPath := write("policy.json", b)
	effectsPath := write("effects.json", firewallaudit.ConfigJSON{Scopes: map[string]responseactions.Scope{"edge": {Endpoint: server.URL, TokenEnv: "ABSENT_AUDIT_REPLAY_TOKEN", Network: enforcer.Scope{Hook: "input", Interface: "eth0", DestinationCIDR: "198.51.100.0/24", Protocol: "udp", Port: 53}}}})
	output := filepath.Join(dir, "audit.jsonl")
	args, _ := json.Marshal([]string{"--read", filepath.Join(dir, "*.pcap"), "--out", filepath.Join(dir, "out"), "--include", "DNS,Alert", "--null", "--quiet", "--http", "", "--dpi=false", "--scatter=false", "--macDB=false", "--serviceDB=false", "--geoDB=false", "--workers", "1", "--firewall-policy", policyPath, "--firewall-effects-config", effectsPath})
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	process := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestCaptureReplayProcess$", "-test.count=1")
	for _, v := range os.Environ() {
		if !strings.HasPrefix(v, "NC_") && !strings.HasPrefix(v, "FIREWALL_AUDIT_") && !strings.HasPrefix(v, "ABSENT_AUDIT_REPLAY_TOKEN=") {
			process.Env = append(process.Env, v)
		}
	}
	process.Env = append(process.Env, "FIREWALL_AUDIT_REPLAY="+string(args), "FIREWALL_AUDIT_OUTPUT="+output)
	commandOutput, processErr := process.CombinedOutput()
	if processErr != nil {
		t.Fatalf("capture replay: %v\n%s", processErr, commandOutput)
	}
	raw, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	matches := 0
	summary := map[string]int{}
	for {
		var result firewallaudit.Result
		if err = decoder.Decode(&result); err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if !result.DryRun || len(result.Decision.Effects) > 0 || result.EffectsRequested > 0 || result.Phase != "retrospective" {
			t.Fatalf("unsafe replay result: %+v", result)
		}
		if result.RecordType == "DNS" && result.Decision.RuleID == "dns" {
			matches++
		}
		summary[result.RecordType+":"+result.Reason]++
	}
	if expected < 2 || matches != expected || calls.Load() != 0 || connections.Load() != 0 {
		t.Fatalf("multi-file matches=%d, network calls=%d, connections=%d, records=%v\n%s", matches, calls.Load(), connections.Load(), summary, commandOutput)
	}
	t.Logf("multi-file CLI replay: %d DNS field predicate matches; %d network calls", matches, calls.Load())
}
