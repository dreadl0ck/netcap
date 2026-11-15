//go:build !appstore

package webui

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	decoderconfig "github.com/dreadl0ck/netcap/internal/decoder/config"
	pb "github.com/dreadl0ck/netcap/internal/decoder/stream/protobuf"
)

// The owned helper emits argv/env only. It never opens a capture interface.
func init() {
	if os.Getenv("NETCAP_TEST_MCP_HELPER") != "1" {
		return
	}
	out := ""
	for i, arg := range os.Args {
		if arg == "-out" && i+1 < len(os.Args) {
			out = os.Args[i+1]
		}
	}
	if out == "" {
		os.Exit(91)
	}
	raw, _ := json.Marshal(struct{ Args, Env []string }{os.Args[1:], os.Environ()})
	if os.WriteFile(filepath.Join(out, "helper-invocation.json"), raw, 0600) != nil {
		os.Exit(92)
	}
	os.Exit(0)
}

func TestMCPRuntimeSettingsReachActualHelperAndReanalysis(t *testing.T) {
	oldProto := protoRuntime
	protoRuntime = &protoState{}
	defer func() { protoRuntime = oldProto }()
	decoderconfig.LockInstance()
	oldConfig := decoderconfig.Instance
	decoderconfig.Instance = nil
	decoderconfig.UnlockInstance()
	defer func() {
		decoderconfig.LockInstance()
		decoderconfig.Instance = oldConfig
		decoderconfig.UnlockInstance()
	}()
	oldRegistry := pb.GetSchemaRegistry()
	defer pb.SetSchemaRegistry(oldRegistry)
	t.Setenv("NETCAP_TEST_MCP_HELPER", "1")
	t.Setenv("NC_PROTO_PATHS", "/foreign/ambient")
	t.Setenv("NC_PROTO_MESSAGE_TYPES", "9999:Foreign.Message")
	t.Setenv("NC_PAYLOAD", "true")
	t.Setenv("NC_BPF", "udp port 9")
	t.Setenv("NC_INCLUDE", "UNREQUESTED")
	t.Setenv("NC_EXCLUDE", "UNREQUESTED")
	t.Setenv("NC_CONFIG_ROOT", t.TempDir())
	dir := t.TempDir()
	source := filepath.Join(dir, "source.pcap")
	if err := os.WriteFile(source, []byte("owned test source"), 0600); err != nil {
		t.Fatal(err)
	}
	s := NewServer("127.0.0.1:0", dir, []string{source}, "", false, false, false, nil, &RuntimeConfig{CaptureEvidence: true, FlowExports: true, RetainPackets: true, PacketSegmentBytes: 2 << 20, PacketRetentionBytes: 8 << 20, MaxRetainedTCPBytes: 4 << 20}, true)
	s.MarkFileCompleted(source)
	post := func(handler http.HandlerFunc, body string, method string) {
		t.Helper()
		w := httptest.NewRecorder()
		handler(w, httptest.NewRequest(method, "/", strings.NewReader(body)))
		if w.Code != 200 {
			t.Fatalf("settings rejected: %d %s", w.Code, w.Body)
		}
	}
	protoDir := filepath.Join(t.TempDir(), "schemas,fixture")
	if err := os.Mkdir(protoDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(protoDir, "fixture.proto"), []byte(`syntax="proto3";package fixture;message Message { string name=1; }`), 0600); err != nil {
		t.Fatal(err)
	}
	pathBody, _ := json.Marshal(map[string]string{"path": protoDir})
	post(s.handleProtoSearchPaths, string(pathBody), http.MethodPost)
	post(s.handleProtoMappings, `{"port":1234,"messageType":"fixture.Message"}`, http.MethodPost)
	post(s.handleProtoPreferences, `{"showAlternatives":true}`, http.MethodPost)
	post(s.handleFeatures, `{"name":"network-detection","enabled":false}`, http.MethodPost)
	post(s.handleFeatures, `{"name":"dns-resolution-context","enabled":true}`, http.MethodPost)
	parseArgs := func(args []string) map[string]any {
		t.Helper()
		command := exec.Command(filepath.Join(runtime.GOROOT(), "bin", "go"), append([]string{"run", "-tags=nodpi,noyara,nomagika", "./testdata/parse_capture"}, args...)...)
		command.Env = append(helperEnvironment(), "GOWORK=off")
		var stderr bytes.Buffer
		command.Stderr = &stderr
		raw, err := command.Output()
		if err != nil {
			t.Fatalf("actual capture CLI rejected generated helper argv: %v\n%s\n%s", err, raw, stderr.String())
		}
		var result map[string]any
		if err := json.Unmarshal(raw, &result); err != nil {
			t.Fatalf("capture CLI parser output: %v\n%s", err, raw)
		}
		return result
	}
	firstJob := true
	runChild := func() []string {
		t.Helper()
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/api/reanalyze", strings.NewReader(`{}`))
		s.queueChildAnalysis(w, r, source, dir, "", "127.0.0.1", nil, "")
		if w.Code != 200 && w.Code != 202 {
			t.Fatalf("reanalysis admission: %d %s", w.Code, w.Body)
		}
		job := <-s.jobQueue
		if firstJob {
			post(s.handleFeatures, `{"name":"network-detection","enabled":true}`, http.MethodPost)
			if err := os.WriteFile(filepath.Join(protoDir, "fixture.proto"), []byte("invalid changed schema"), 0600); err != nil {
				t.Fatal(err)
			}
			registry, err := pb.NewSchemaRegistry(job.settings.Protobuf.Paths)
			if err != nil {
				t.Fatalf("queued schema snapshot changed: %v", err)
			}
			if _, ok := registry.LookupMessage("fixture.Message"); !ok {
				t.Fatal("frozen schema lost configured type")
			}
		}
		s.runAnalysis(job)
		job.processingDone()
		if firstJob {
			os.WriteFile(filepath.Join(protoDir, "fixture.proto"), []byte(`syntax="proto3";package fixture;message Message { string name=1; }`), 0600)
			firstJob = false
		}
		b, err := os.ReadFile(filepath.Join(job.OutputDir, "helper-invocation.json"))
		if err != nil {
			t.Fatal(err)
		}
		var invocation struct{ Args, Env []string }
		if err := json.Unmarshal(b, &invocation); err != nil {
			t.Fatal(err)
		}
		for _, env := range invocation.Env {
			if strings.HasPrefix(env, "NC_PROTO_") {
				t.Fatalf("ambient schema state leaked into helper: %s", env)
			}
		}
		return invocation.Args
	}
	firstArgs := runChild()
	first := strings.Join(firstArgs, "\n")
	for _, want := range []string{"-network-detection=false", "-dns-resolution-context=true", "-proto-message-types=1234:fixture.Message", "-proto-show-alternatives=true", "-packet-retention-mb=8", "-max-retained-tcp-bytes=4194304", "-dpi=false"} {
		if !strings.Contains(first, want) {
			t.Fatalf("helper lost %q:\n%s", want, first)
		}
	}
	parsed := parseArgs(firstArgs)
	if parsed["dpi"] != false || parsed["payload"] != false || parsed["bpf"] != "" || parsed["include"] != "" || parsed["exclude"] != "" {
		t.Fatalf("explicit false/empty job settings lost to ambient environment: %#v", parsed)
	}
	if paths, ok := parsed["paths"].([]any); !ok || len(paths) != 1 || strings.Contains(paths[0].(string), ",") {
		t.Fatalf("CSV schema paths were split: %#v", parsed)
	}
	post(s.handleProtoSearchPaths, string(pathBody), http.MethodDelete)
	post(s.handleProtoMappings, `{"port":1234}`, http.MethodDelete)
	post(s.handleProtoPreferences, `{"showAlternatives":false}`, http.MethodPost)
	post(s.handleFeatures, `{"name":"network-detection","enabled":true}`, http.MethodPost)
	post(s.handleAnalysisSettings, `{"retentionMB":16,"payload":true,"dpiModules":"go","incrementalHTTP":true}`, http.MethodPost)
	post(s.handleDecoderConfig, `{"includeDecoders":"TCP,DNS","excludeDecoders":""}`, http.MethodPost)
	secondArgs := runChild()
	second := strings.Join(secondArgs, "\n")
	if strings.Contains(second, "-proto-paths=") || strings.Contains(second, "-proto-message-types=") || !strings.Contains(second, "-proto-show-alternatives=false") || !strings.Contains(second, "-network-detection=true") {
		t.Fatalf("cleared settings were resurrected: %s", second)
	}
	parsed = parseArgs(secondArgs)
	if parsed["payload"] != true || parsed["retentionMB"] != float64(16) || parsed["modules"] != "go" || parsed["include"] != "TCP,DNS" {
		t.Fatalf("runtime patch not consumed by real capture flags: %#v", parsed)
	}
	_ = s.Stop(context.Background())
}
