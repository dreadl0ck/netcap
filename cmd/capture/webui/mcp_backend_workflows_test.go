package webui

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	streamutils "github.com/dreadl0ck/netcap/internal/decoder/stream/utils"
	"github.com/dreadl0ck/netcap/internal/evidence"
	"github.com/dreadl0ck/netcap/internal/protocoltest"
	"github.com/dreadl0ck/netcap/types"
	"github.com/gogo/protobuf/proto"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

func TestMCPExplicitConfigAndAuthenticationSelection(t *testing.T) {
	a, b := t.TempDir(), t.TempDir()
	s := NewServer("127.0.0.1:0", a, []string{"/a.pcap", "/b.pcap"}, "", false, false, false, nil, nil, false)
	s.SetFileOutputDir("/a.pcap", a)
	s.SetFileOutputDir("/b.pcap", b)
	s.activeInputFile = "/a.pcap"
	s.fileBPFFilters["/a.pcap"] = "tcp port 1111"
	s.fileBPFFilters["/b.pcap"] = "udp port 2222"
	for _, item := range []struct{ dir, user string }{{a, "ALICE"}, {b, "BOB"}} {
		writeTimelineAuditFile(t, item.dir, "TACACS", types.Type_NC_TACACS, []proto.Message{&types.TACACS{User: item.user, StatusName: "pass"}})
	}
	for _, handler := range []http.HandlerFunc{s.handleConfig, s.handleAuthActivity} {
		w := httptest.NewRecorder()
		handler(w, httptest.NewRequest(http.MethodGet, "/?inputFile=%2Fb.pcap", nil))
		if w.Code != 200 {
			t.Fatalf("selected request failed: %d %s", w.Code, w.Body)
		}
		text := w.Body.String()
		if strings.Contains(text, "ALICE") || strings.Contains(text, `"value":"/a.pcap"`) {
			t.Fatalf("global selection leaked: %s", text)
		}
		bad := httptest.NewRecorder()
		handler(bad, httptest.NewRequest(http.MethodGet, "/?inputFile=%2Fforeign.pcap", nil))
		if bad.Code != 404 {
			t.Fatalf("unknown selector became active data: %d", bad.Code)
		}
	}
	w := httptest.NewRecorder()
	s.handleAuthActivity(w, httptest.NewRequest("GET", "/?inputFile=%2Fb.pcap&limit=1&offset=0", nil))
	if !strings.Contains(w.Body.String(), "BOB") {
		t.Fatal(w.Body)
	}
	if s.activeInputFile != "/a.pcap" {
		t.Fatal("explicit read mutated active capture")
	}
	w = httptest.NewRecorder()
	s.handleConfig(w, httptest.NewRequest("GET", "/?inputFile=%2Fb.pcap", nil))
	if !strings.Contains(w.Body.String(), "udp port 2222") {
		t.Fatal("config lost selected input BPF")
	}
	snapshot, _ := json.Marshal(jobSettings{Version: 1, BPF: "tcp port 8443", IncludeDecoders: "TLS", Payload: true})
	os.WriteFile(filepath.Join(b, "analysis-runtime.json"), snapshot, 0600)
	w = httptest.NewRecorder()
	s.handleConfig(w, httptest.NewRequest("GET", "/?inputFile=%2Fb.pcap", nil))
	if !strings.Contains(w.Body.String(), "tcp port 8443") || !strings.Contains(w.Body.String(), "admittedSettings") {
		t.Fatal("historical selected settings were rebound to current configuration")
	}
}

func TestMCPLocalHTTPUsesDistinctBackendCredential(t *testing.T) {
	t.Setenv(EnvMCPAdminToken, "external-mcp-admin")
	s := NewServer("127.0.0.1:0", t.TempDir(), nil, "", false, false, false, nil, nil, false)
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	defer s.Stop(context.Background())
	request := func(path, token, body string) (int, string) {
		t.Helper()
		r, _ := http.NewRequest("POST", s.GetURL()+path, strings.NewReader(body))
		r.Header.Set("Authorization", "Bearer "+token)
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Accept", "application/json, text/event-stream")
		response, err := http.DefaultClient.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		raw, _ := io.ReadAll(response.Body)
		return response.StatusCode, string(raw)
	}
	status, body := request("/mcp", "external-mcp-admin", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_features","arguments":{}}}`)
	if status != 200 || strings.Contains(body, `"isError":true`) || !strings.Contains(body, "dns-resolution-context") {
		t.Fatalf("MCP loopback could not authenticate independently: %d %s", status, body)
	}
	if status, _ := request("/api/features", "external-mcp-admin", `{}`); status != 401 {
		t.Fatal("external MCP credential bypassed per-run API authentication")
	}
	if status, _ := request("/mcp", "wrong", `{}`); status != 401 {
		t.Fatal("MCP accepted an invalid credential")
	}
}

func TestMCPServiceSelectorsRetainOwnership(t *testing.T) {
	manager := NewSessionManager(10, 60, 10)
	manager.AddSession(&SessionInfo{SessionID: "private", IP: "192.0.2.2", InputFile: "/private.pcap", OutputDir: t.TempDir()})
	s := &Server{isServiceMode: true, sessionManager: manager}
	for _, handler := range []http.HandlerFunc{s.handleConfig, s.handleAuthActivity} {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", "/?sessionId=private", nil)
		r.RemoteAddr = "192.0.2.1:1234"
		handler(w, r)
		if w.Code != 403 {
			t.Fatalf("foreign selected data became available: %d", w.Code)
		}
	}
}

func TestMCPSourceGrammarAndTLSUseBoundSnapshots(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "source.pcap")
	source := []byte("registered fixture capture")
	os.WriteFile(input, source, 0600)
	s := NewServer("127.0.0.1:0", dir, []string{input}, "", false, false, false, nil, nil, false)
	stream := filepath.Join(dir, "stream-evidence", "stream-bound")
	os.MkdirAll(stream, 0700)
	data := []byte{7, 9}
	digest := sha256.Sum256(data)
	manifest := streamutils.StreamEvidenceManifest{Version: 1, Protocol: "TCP", Status: "no-reported-gap", Client: streamutils.StreamEvidenceFile{Name: "client.bin", Length: 2, SHA256: hex.EncodeToString(digest[:])}}
	raw, _ := json.Marshal(manifest)
	binding := sha256.Sum256(raw)
	os.WriteFile(filepath.Join(stream, "manifest.json"), raw, 0600)
	os.WriteFile(filepath.Join(stream, "client.bin"), data, 0600)
	grammar := protocoltest.Grammar{Version: 1, Framing: protocoltest.Framing{Kind: "fixed", FixedSize: 2, MaxBytes: 8}, MaxFrames: 2, Fields: []protocoltest.FieldSpec{{Name: "opcode", Kind: "unsigned", Length: 1, ByteOrder: "big", Hypothesis: "declared field"}}}
	body, _ := json.Marshal(map[string]any{"id": "stream-bound", "direction": "client", "manifestSHA256": hex.EncodeToString(binding[:]), "grammar": grammar})
	w := httptest.NewRecorder()
	s.handleInterpretStream(w, httptest.NewRequest("POST", "/?inputFile="+url.QueryEscape(input), bytes.NewReader(body)))
	if w.Code != 200 || !strings.Contains(w.Body.String(), "inputSHA256") {
		t.Fatalf("bound grammar: %d %s", w.Code, w.Body)
	}
	manifest.Status = "partial"
	raw, _ = json.Marshal(manifest)
	os.WriteFile(filepath.Join(stream, "manifest.json"), raw, 0600)
	bad := httptest.NewRecorder()
	s.handleInterpretStream(bad, httptest.NewRequest("POST", "/?inputFile="+url.QueryEscape(input), bytes.NewReader(body)))
	if bad.Code != 422 {
		t.Fatal("stale/gapped grammar input was accepted")
	}
	keyLog := filepath.Join(t.TempDir(), "secret.log")
	os.WriteFile(keyLog, []byte("PRIVATE_SESSION_SECRET"), 0600)
	sourceHash := sha256.Sum256(source)
	calls := 0
	s.tlsAnalyzer = func(ctx context.Context, pcap, key string, index int) (protocoltest.TLSCaptureResult, error) {
		calls++
		if pcap == input || key == keyLog {
			t.Error("TLS analyzer received mutable original paths")
		}
		info, err := os.Stat(key)
		if err != nil || info.Mode().Perm() != 0600 {
			t.Error("TLS secret snapshot is not private")
		}
		b, _ := os.ReadFile(pcap)
		if !bytes.Equal(b, source) {
			t.Error("TLS source snapshot changed")
		}
		return protocoltest.TLSCaptureResult{Version: 1, InputSHA256: hex.EncodeToString(sourceHash[:]), Stream: index, Limitations: []string{"fake owned adapter"}}, nil
	}
	tlsBody, _ := json.Marshal(map[string]any{"keyLog": keyLog, "sourceSHA256": hex.EncodeToString(sourceHash[:]), "stream": 0})
	w = httptest.NewRecorder()
	s.handleTLSCapture(w, httptest.NewRequest("POST", "/?inputFile="+url.QueryEscape(input), bytes.NewReader(tlsBody)))
	if w.Code != 200 || calls != 1 || strings.Contains(w.Body.String(), "PRIVATE_SESSION_SECRET") || strings.Contains(w.Body.String(), keyLog) {
		t.Fatalf("TLS snapshot/privacy contract: %d %s", w.Code, w.Body)
	}
	wrong, _ := json.Marshal(map[string]any{"keyLog": keyLog, "sourceSHA256": strings.Repeat("0", 64), "stream": 0})
	w = httptest.NewRecorder()
	s.handleTLSCapture(w, httptest.NewRequest("POST", "/?inputFile="+url.QueryEscape(input), bytes.NewReader(wrong)))
	if w.Code != 409 || calls != 1 {
		t.Fatal("stale TLS source reached adapter")
	}
	s.isServiceMode = true
	w = httptest.NewRecorder()
	s.handleTLSCapture(w, httptest.NewRequest("POST", "/", bytes.NewReader(tlsBody)))
	if w.Code != 403 {
		t.Fatal("service tenant gained host secret-file access")
	}
}

func TestMCPOwnedLiveCaptureFakeRunnerLifecycle(t *testing.T) {
	interfaces, err := net.Interfaces()
	if err != nil || len(interfaces) == 0 {
		t.Skip("no interface discovery available")
	}
	nic := interfaces[0].Name
	t.Setenv("NC_LIVE_INTERFACES", nic)
	s := NewServer("127.0.0.1:0", t.TempDir(), nil, "", false, false, false, nil, nil, false)
	var arguments []string
	s.liveRunner = func(ctx context.Context, args []string, out string) (func() error, error) {
		arguments = append([]string{}, args...)
		return func() error { <-ctx.Done(); return nil }, nil
	}
	body := fmt.Sprintf(`{"interface":%q,"durationSeconds":30,"retentionMB":2}`, nic)
	w := httptest.NewRecorder()
	s.handleOwnedLiveCapture(w, httptest.NewRequest(http.MethodPost, "/api/live-capture", strings.NewReader(body)))
	if w.Code != 202 {
		t.Fatalf("live admission: %d %s", w.Code, w.Body)
	}
	var result struct {
		ID string `json:"session_id"`
	}
	json.Unmarshal(w.Body.Bytes(), &result)
	for _, want := range []string{"-promisc=false", "-retain-packets=true", "-packet-retention-mb=2", "-max-retained-tcp-bytes=16777216"} {
		if !strings.Contains(strings.Join(arguments, "\n"), want) {
			t.Fatalf("missing live bound %s", want)
		}
	}
	busy := httptest.NewRecorder()
	s.handleOwnedLiveCapture(busy, httptest.NewRequest("POST", "/api/live-capture", strings.NewReader(body)))
	if busy.Code != 409 {
		t.Fatal("accepted overlapping live capture")
	}
	foreign := httptest.NewRecorder()
	s.handleStopCapture(foreign, httptest.NewRequest("POST", "/api/stop-capture?sessionId=foreign", nil))
	if foreign.Code != 404 {
		t.Fatal("foreign stop was admitted")
	}
	stop := httptest.NewRecorder()
	s.handleStopCapture(stop, httptest.NewRequest("POST", "/api/stop-capture?sessionId="+result.ID, nil))
	if stop.Code != 200 {
		t.Fatalf("owned stop: %d %s", stop.Code, stop.Body)
	}
	done := make(chan struct{})
	go func() { s.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("owned runner did not stop")
	}
	s.mu.RLock()
	completed := s.ownedLive.Completed
	errText := s.ownedLive.Error
	s.mu.RUnlock()
	if !completed || errText != "" {
		t.Fatalf("owned capture did not complete: %v %q", completed, errText)
	}
	listed := httptest.NewRecorder()
	s.handleInputFiles(listed, httptest.NewRequest("GET", "/api/files/input", nil))
	if !strings.Contains(listed.Body.String(), result.ID) || !strings.Contains(listed.Body.String(), "live-retained-segments") {
		t.Fatalf("owned capture not discoverable: %s", listed.Body)
	}
	deleted := httptest.NewRecorder()
	s.handleOwnedLiveCapture(deleted, httptest.NewRequest("DELETE", "/api/live-capture?sessionId="+result.ID, nil))
	if deleted.Code != 200 {
		t.Fatalf("owned cleanup: %d %s", deleted.Code, deleted.Body)
	}
	s.isServiceMode = true
	rejected := httptest.NewRecorder()
	s.handleOwnedLiveCapture(rejected, httptest.NewRequest("POST", "/api/live-capture", strings.NewReader(body)))
	if rejected.Code != 403 {
		t.Fatal("tenant admitted host traffic")
	}
}

func TestMCPPacketExportBindsRetainedSegmentAndRun(t *testing.T) {
	dir := t.TempDir()
	capture, err := evidence.NewCapture(context.Background(), dir, evidence.CaptureConfig{Kind: "live", Source: "fixture0", RetainPackets: true, SegmentBytes: 1 << 20, RetentionBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	data := make([]byte, 14)
	if err := capture.Observe(data, gopacket.CaptureInfo{Timestamp: time.Unix(1700000000, 3), CaptureLength: 14, Length: 14}, layers.LinkTypeEthernet); err != nil {
		t.Fatal(err)
	}
	if err := capture.Close("done", 1, 0, nil); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "capture-manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest evidence.CaptureManifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}
	if len(manifest.Segments) != 1 {
		t.Fatal("fixture did not retain one segment")
	}
	segment := manifest.Segments[0]
	s := NewServer("127.0.0.1:0", dir, []string{"/virtual-live.pcap"}, "", false, false, false, nil, nil, false)
	query := url.Values{"inputFile": {"/virtual-live.pcap"}, "runId": {manifest.RunID}, "sourceSHA256": {segment.SHA256}, "segment": {segment.Name}, "maxPackets": {"1"}}
	request := func() *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		s.handlePacketExport(w, httptest.NewRequest("GET", "/?"+query.Encode(), nil))
		return w
	}
	w := request()
	if w.Code != 200 || w.Header().Get("Content-Type") != "application/zip" {
		t.Fatalf("packet export: %d %s", w.Code, w.Body)
	}
	archive, err := zip.NewReader(bytes.NewReader(w.Body.Bytes()), int64(w.Body.Len()))
	if err != nil {
		t.Fatal(err)
	}
	var exported evidence.PacketManifest
	for _, file := range archive.File {
		if file.Name == "manifest.json" {
			f, err := file.Open()
			if err != nil {
				t.Fatal(err)
			}
			err = json.NewDecoder(f).Decode(&exported)
			f.Close()
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	if exported.SourceSHA256 != segment.SHA256 || exported.Selected != 1 || len(exported.Limitations) == 0 {
		t.Fatalf("archive lost source qualification: %+v", exported)
	}
	query.Set("runId", "stale")
	if w := request(); w.Code != 409 {
		t.Fatal("stale capture generation exported")
	}
	query.Set("runId", manifest.RunID)
	query.Set("segment", "../foreign")
	if w := request(); w.Code != 409 {
		t.Fatal("unregistered segment exported")
	}
	query.Set("segment", segment.Name)
	manifest.Segments[0].State = "expired"
	raw, _ = json.Marshal(manifest)
	os.WriteFile(filepath.Join(dir, "capture-manifest.json"), raw, 0600)
	if w := request(); w.Code != 409 {
		t.Fatal("expired segment was silently exported")
	}
}

func TestMCPAnalysisSettingsPatchIsBoundedAndDoesNotWipe(t *testing.T) {
	s := NewServer("127.0.0.1:0", t.TempDir(), nil, "", false, false, false, nil, &RuntimeConfig{CaptureEvidence: true, FlowExports: true, PacketSegmentBytes: 2 << 20, PacketRetentionBytes: 8 << 20}, false)
	patch := func(body string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		s.handleAnalysisSettings(w, httptest.NewRequest("POST", "/api/analysis/settings", strings.NewReader(body)))
		return w
	}
	if w := patch(`{"payload":true,"retentionMB":16,"flowExports":false}`); w.Code != 200 {
		t.Fatal(w.Body)
	}
	if w := patch(`{"payload":false}`); w.Code != 200 || !strings.Contains(w.Body.String(), `"retentionMB":16`) || !strings.Contains(w.Body.String(), `"flowExports":false`) {
		t.Fatal("omitted settings were reset", w.Body)
	}
	for _, body := range []string{`{}`, `{"payload":null}`, `{"retentionMB":0}`, `{"segmentMB":32,"retentionMB":16}`, `{"flowExportPorts":"65536"}`, `{"dpiModules":"invented"}`, `{"shell":"anything"}`} {
		if w := patch(body); w.Code != 400 {
			t.Fatalf("invalid patch accepted: %s: %d", body, w.Code)
		}
	}
	if s.runtimeConfig.PacketRetentionBytes != 16<<20 || s.runtimeConfig.FlowExports {
		t.Fatal("invalid request partially changed settings")
	}
}

func TestMCPConcurrentRuntimePatchAndRead(t *testing.T) {
	s := NewServer("127.0.0.1:0", t.TempDir(), []string{"/known.pcap"}, "", false, false, false, nil, nil, false)
	var workers sync.WaitGroup
	for i := 0; i < 4; i++ {
		workers.Add(1)
		go func(index int) {
			defer workers.Done()
			for n := 0; n < 20; n++ {
				w := httptest.NewRecorder()
				if index%2 == 0 {
					s.handleAnalysisSettings(w, httptest.NewRequest("POST", "/api/analysis/settings", strings.NewReader(fmt.Sprintf(`{"payload":%t}`, n%2 == 0))))
				} else {
					s.handleConfig(w, httptest.NewRequest("GET", "/api/config?inputFile=%2Fknown.pcap", nil))
				}
				if w.Code != 200 {
					t.Errorf("concurrent configuration call failed: %d", w.Code)
				}
			}
		}(i)
	}
	workers.Wait()
}

func TestMCPStreamContentPagesVerifySourceAndConfinement(t *testing.T) {
	out := t.TempDir()
	stream := filepath.Join(out, "stream-evidence", "stream-fixture")
	os.MkdirAll(stream, 0700)
	data := []byte("directional bytes")
	hash := sha256.Sum256(data)
	manifest := streamutils.StreamEvidenceManifest{Version: 1, Protocol: "TCP", Status: "partial", Client: streamutils.StreamEvidenceFile{Name: "client.bin", Length: int64(len(data)), SHA256: hex.EncodeToString(hash[:])}, Limitations: []string{"missing preceding handshake"}}
	encoded, _ := json.Marshal(manifest)
	os.WriteFile(filepath.Join(stream, "manifest.json"), encoded, 0600)
	os.WriteFile(filepath.Join(stream, "client.bin"), data, 0600)
	s := NewServer("127.0.0.1:0", out, []string{"/fixture.pcap"}, "", false, false, false, nil, nil, false)
	request := func(query url.Values) *httptest.ResponseRecorder {
		t.Helper()
		query.Set("inputFile", "/fixture.pcap")
		w := httptest.NewRecorder()
		s.handleStreamContent(w, httptest.NewRequest("GET", "/?"+query.Encode(), nil))
		return w
	}
	q := url.Values{"id": {"stream-fixture"}, "direction": {"client"}, "limit": {"4"}}
	first := request(q)
	if first.Code != 200 || !strings.Contains(first.Body.String(), "missing preceding handshake") {
		t.Fatalf("stream page: %d %s", first.Code, first.Body)
	}
	var page struct {
		Data     []byte
		Manifest string `json:"manifestSHA256"`
	}
	json.Unmarshal(first.Body.Bytes(), &page)
	if string(page.Data) != "dire" {
		t.Fatal("wrong directional bytes")
	}
	q.Set("offset", "4")
	if w := request(q); w.Code != 409 {
		t.Fatal("unbound subsequent page accepted")
	}
	q.Set("manifestSHA256", page.Manifest)
	if w := request(q); w.Code != 200 {
		t.Fatal(w.Body)
	}
	q.Set("offset", "100")
	end := request(q)
	var empty struct {
		Data   []byte
		Offset int64
		More   bool `json:"hasMore"`
	}
	if err := json.Unmarshal(end.Body.Bytes(), &empty); err != nil || end.Code != 200 || len(empty.Data) != 0 || empty.More || empty.Offset != 100 {
		t.Fatalf("beyond-EOF page: %d %s %v", end.Code, end.Body.String(), err)
	}
	q.Set("manifestSHA256", strings.Repeat("0", 64))
	if w := request(q); w.Code != 409 {
		t.Fatal("beyond-EOF request bypassed manifest identity")
	}
	q.Set("manifestSHA256", page.Manifest)
	os.WriteFile(filepath.Join(stream, "client.bin"), []byte("modified evidence"), 0600)
	if w := request(q); w.Code != 409 {
		t.Fatal("changed stream bytes accepted")
	}
	os.Remove(filepath.Join(stream, "client.bin"))
	target := filepath.Join(t.TempDir(), "foreign.bin")
	os.WriteFile(target, data, 0600)
	os.Symlink(target, filepath.Join(stream, "client.bin"))
	if w := request(q); w.Code != 404 {
		t.Fatal("stored symlink escaped source root")
	}
}
