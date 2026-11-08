package webui

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dreadl0ck/netcap/internal/analyst"
	"github.com/dreadl0ck/netcap/internal/evidence"
	"github.com/dreadl0ck/netcap/types"
	"github.com/gogo/protobuf/proto"
)

func boundFixture(t *testing.T, id string) (string, analyst.Binding) {
	t.Helper()
	dir := t.TempDir()
	data, _ := json.Marshal(evidence.CaptureManifest{Version: 1, RunID: id, InputSHA256: strings.Repeat("a", 64), Status: "done"})
	if err := os.WriteFile(filepath.Join(dir, "capture-manifest.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, evidence.AuditReadyFile), []byte(`{"version":1,"runId":"`+id+`"}`), 0600); err != nil {
		t.Fatal(err)
	}
	writeTimelineAuditFile(t, dir, "Connection", types.Type_NC_Connection, []proto.Message{&types.Connection{TimestampFirst: 1700000000000000001, TimestampLast: 1700000000000000002, SrcIP: "192.0.2.1", DstIP: "192.0.2.2", TransportProto: "TCP"}, &types.Connection{TimestampFirst: 1700000000000000001, TimestampLast: 1700000000000000002, SrcIP: "192.0.2.1", DstIP: "192.0.2.2", TransportProto: "TCP"}})
	binding, err := analyst.Bind(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	return dir, binding
}
func analystCall(t *testing.T, handler http.HandlerFunc, body any) *httptest.ResponseRecorder {
	t.Helper()
	data, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/api/analyst", bytes.NewReader(data))
	handler(w, r)
	return w
}

func TestAnalystCatalogueRealHandlersRetainExplicitOccurrences(t *testing.T) {
	a, ab := boundFixture(t, "one")
	b, bb := boundFixture(t, "two")
	s := &Server{outDir: a, inputFiles: []string{"/a.pcap", "/b.pcap"}, fileOutputDirs: map[string]string{"/a.pcap": a, "/b.pcap": b}}
	src := analystSource{InputFile: "/a.pcap", Binding: ab}
	request := catalogueRequest{Sources: []analystSource{src, {InputFile: "/b.pcap", Binding: bb}}, Query: analyst.Query{Kind: "endpoint", Value: "192.0.2.1", Types: []string{"Connection"}}}
	w := analystCall(t, s.handleAnalystCatalogue, request)
	if w.Code != 200 {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	var result analyst.Catalogue
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if len(result.Occurrences) != 4 || result.Novelty != "observed-in-included-baseline" {
		t.Fatalf("lost occurrences %+v", result)
	}
	ref := result.Occurrences[0].Reference
	resolved := analystCall(t, s.handleAnalystOccurrence, analyst.ResolveRequest{Source: src, Reference: ref})
	if resolved.Code != 200 || !strings.Contains(resolved.Body.String(), `"TimestampFirst":"1700000000000000001"`) {
		t.Fatalf("exact read %d %s", resolved.Code, resolved.Body.String())
	}
	writeTimelineAuditFile(t, a, "Connection", types.Type_NC_Connection, []proto.Message{&types.Connection{TimestampFirst: 1700000000000000001, SrcIP: "198.51.100.1"}})
	resolved = analystCall(t, s.handleAnalystOccurrence, analyst.ResolveRequest{Source: src, Reference: ref})
	if resolved.Code != 409 {
		t.Fatalf("stale file rebound: %d %s", resolved.Code, resolved.Body.String())
	}
}

func TestAnalystOwnershipSchemaAndCancellation(t *testing.T) {
	a, ab := boundFixture(t, "one")
	b, bb := boundFixture(t, "two")
	s := &Server{isServiceMode: true, sessionManager: &SessionManager{sessions: map[string]*SessionInfo{"owned": {SessionID: "owned", IP: "192.0.2.1", OutputDir: a}, "private": {SessionID: "private", IP: "192.0.2.2", OutputDir: b}, "public": {SessionID: "public", IsPreloaded: true, OutputDir: a}}}}
	body := catalogueRequest{Sources: []analystSource{{SessionID: "owned", Binding: ab}, {SessionID: "private", Binding: bb}}, Query: analyst.Query{Kind: "endpoint", Value: "192.0.2.1", Types: []string{"Connection"}}}
	data, _ := json.Marshal(body)
	r := httptest.NewRequest("POST", "/api/analyst/catalogue", bytes.NewReader(data))
	r.RemoteAddr = "192.0.2.1:123"
	w := httptest.NewRecorder()
	s.handleAnalystCatalogue(w, r)
	if w.Code != 403 || strings.Contains(w.Body.String(), `"occurrences"`) {
		t.Fatalf("private source leaked %d %s", w.Code, w.Body.String())
	}
	for _, bad := range []string{`{"sources":[],"sources":[]}`, `{"sources":[],"unknown":1}`, `{} {}`, `{"source":{"sessionId":"owned","sessionId":"private"}}`} {
		w = httptest.NewRecorder()
		s.handleAnalystCatalogue(w, httptest.NewRequest("POST", "/api/analyst/catalogue", strings.NewReader(bad)))
		if w.Code != 400 {
			t.Fatalf("schema accepted %s: %d", bad, w.Code)
		}
	}
	w = analystCall(t, s.handleAnalystWorkspace, analyst.WorkspaceRequest{Source: analystSource{SessionID: "public", Binding: ab}})
	if w.Code != 403 {
		t.Fatalf("shared public workspace allowed: %d", w.Code)
	}
	local := &Server{inputFiles: []string{"/a.pcap"}, fileOutputDirs: map[string]string{"/a.pcap": a}}
	data, _ = json.Marshal(catalogueRequest{Sources: []analystSource{{InputFile: "/a.pcap", Binding: ab}}, Query: body.Query})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r = httptest.NewRequest("POST", "/api/analyst/catalogue", bytes.NewReader(data)).WithContext(ctx)
	w = httptest.NewRecorder()
	local.handleAnalystCatalogue(w, r)
	if w.Code != 408 {
		t.Fatalf("cancellation %d", w.Code)
	}
}

func TestBoundTableStreamAndTimelineShareReference(t *testing.T) {
	dir, binding := boundFixture(t, "bound")
	q := url.Values{"inputFile": {"/a.pcap"}, "evidence": {"1"}, "runId": {binding.RunID}, "sourceSHA256": {binding.SourceSHA256}, "manifestSHA256": {binding.ManifestSHA256}, "offset": {"1"}, "limit": {"1"}}
	w := httptest.NewRecorder()
	HandleAuditStream(w, httptest.NewRequest("GET", "/api/audit/Connection/stream?"+q.Encode(), nil), filepath.Join(dir, "Connection.ncap.gz"), "Connection")
	if w.Code != 200 {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	var ref analyst.Reference
	for _, line := range strings.Split(w.Body.String(), "\n") {
		if strings.HasPrefix(line, "data: ") && strings.Contains(line, "_netcapOccurrence") {
			var row struct {
				Reference analyst.Reference `json:"_netcapOccurrence"`
			}
			if err := json.Unmarshal([]byte(strings.TrimPrefix(line, "data: ")), &row); err != nil {
				t.Fatal(err)
			}
			ref = row.Reference
		}
	}
	if ref.Ordinal != "1" || ref.Binding != binding {
		t.Fatalf("stream identity %+v", ref)
	}
	events := []timelineEventJSON{{Type: "Connection", Time: ref.TimestampNs, Ordinal: 1}}
	w = httptest.NewRecorder()
	if !attachTimelineOccurrences(w, httptest.NewRequest("GET", "/api/timeline/events?"+q.Encode(), nil), dir, events) {
		t.Fatalf("timeline %d %s", w.Code, w.Body.String())
	}
	if events[0].Occurrence == nil || *events[0].Occurrence != ref {
		t.Fatal("table/timeline references differ")
	}
	encoded, _ := json.Marshal(ref)
	s := &Server{inputFiles: []string{"/a.pcap"}, fileOutputDirs: map[string]string{"/a.pcap": dir}}
	r := httptest.NewRequest("GET", "/api/timeline/record?inputFile=%2Fa.pcap&reference="+url.QueryEscape(string(encoded)), nil)
	w = httptest.NewRecorder()
	s.handleTimelineRecord(w, r)
	if w.Code != 200 {
		t.Fatalf("bound timeline retrieval %d %s", w.Code, w.Body.String())
	}
	q.Set("manifestSHA256", strings.Repeat("0", 64))
	w = httptest.NewRecorder()
	HandleAuditStream(w, httptest.NewRequest("GET", "/api/audit/Connection/stream?"+q.Encode(), nil), filepath.Join(dir, "Connection.ncap.gz"), "Connection")
	if w.Code != 409 {
		t.Fatal("stale stream binding accepted")
	}
}

func TestReviewedReproductionRejectsChangedLog(t *testing.T) {
	dir, binding := boundFixture(t, strings.Repeat("a", 32))
	if err := os.WriteFile(filepath.Join(dir, "capture.log"), []byte("error password=RAW_SENTINEL\ncompleted\n"), 0600); err != nil {
		t.Fatal(err)
	}
	preview, err := analyst.PreviewLog(context.Background(), dir, binding, "capture.log", 1, 2)
	if err != nil {
		t.Fatal(err)
	}
	if err = analyst.ApproveLog(context.Background(), dir, preview); err != nil {
		t.Fatal(err)
	}
	s := &Server{outDir: dir}
	w := httptest.NewRecorder()
	s.handleReproductionBundle(w, httptest.NewRequest("GET", "/api/investigation/reproduction?reviewedLog=true", nil))
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"reviewedLog"`) || strings.Contains(w.Body.String(), "RAW_SENTINEL") {
		t.Fatalf("unsafe attachment %d %s", w.Code, w.Body.String())
	}
	if err = os.WriteFile(filepath.Join(dir, "capture.log"), []byte("changed\ncompleted\n"), 0600); err != nil {
		t.Fatal(err)
	}
	w = httptest.NewRecorder()
	s.handleReproductionBundle(w, httptest.NewRequest("GET", "/api/investigation/reproduction?reviewedLog=true", nil))
	if w.Code != 409 {
		t.Fatalf("stale reviewed attachment accepted %d %s", w.Code, w.Body.String())
	}
}

func TestHTMLCoverageAnnotationsPreserveDoctypeAndImageGraphics(t *testing.T) {
	for _, path := range []string{"/api/charts/data", "/api/hosts/top-talkers", "/api/visualize/sankey"} {
		handler := chartCoverageMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte("<!doctype html><html><body><div id='chart'>" + strings.Repeat("x", 200) + "</div></bo"))
			_, _ = w.Write([]byte("dy></html>"))
		}))
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
		text := w.Body.String()
		if !strings.HasPrefix(text, "<!doctype html>") || strings.Count(text, `data-netcap-coverage="v1"`) != 1 || !strings.Contains(text, "setOption({graphic:") || w.Header().Get("X-Netcap-Coverage") == "" {
			t.Fatalf("coverage missing/corrupt %s", text)
		}
		if strings.Contains(path, "sankey") && !strings.Contains(text, "Schematic") {
			t.Fatal("schematic diagram mislabelled")
		}
	}
}

func TestAnalystRenderedCoverageFixture(t *testing.T) {
	path := os.Getenv("NETCAP_ANALYST_HTML_FIXTURE")
	handler := chartCoverageMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<!doctype html><html><head><script src="/static/echarts/echarts.min.js"></script></head><body><div id="svg" style="width:600px;height:300px"></div><div id="canvas" style="width:600px;height:300px"></div><script>['svg','canvas'].forEach(function(renderer){var chart=echarts.init(document.getElementById(renderer),null,{renderer:renderer});chart.setOption({animation:false,xAxis:{data:['one','two']},yAxis:{},series:[{type:'bar',data:[1,2]}]});});</script></body></html>`))
	}))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequest("GET", "/api/hosts/top-talkers", nil))
	if path == "" {
		expected, err := os.ReadFile(filepath.Join("frontend", "e2e", "analyst-renderer.html"))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(expected, w.Body.Bytes()) {
			t.Fatal("rendered coverage fixture drift; regenerate with NETCAP_ANALYST_HTML_FIXTURE pointing at frontend/e2e/analyst-renderer.html")
		}
		return
	}
	if err := os.WriteFile(path, w.Body.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
}

func TestAnalystHTTPWorkspaceRestartAndSecondaryOwnerRevocation(t *testing.T) {
	a, ab := boundFixture(t, "primary")
	b, bb := boundFixture(t, "secondary")
	manager := &SessionManager{sessions: map[string]*SessionInfo{"primary": {SessionID: "primary", IP: "127.0.0.1", OutputDir: a}, "secondary": {SessionID: "secondary", IP: "127.0.0.1", OutputDir: b}}}
	newAPI := func() *httptest.Server {
		s := &Server{isServiceMode: true, sessionManager: manager}
		mux := http.NewServeMux()
		mux.HandleFunc("/api/analyst/catalogue", s.handleAnalystCatalogue)
		mux.HandleFunc("/api/analyst/workspace", s.handleAnalystWorkspace)
		return httptest.NewServer(s.captureSelectionMiddleware(mux))
	}
	api := newAPI()
	defer func() { api.Close() }()
	call := func(path string, body any) (int, []byte) {
		data, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		response, err := http.Post(api.URL+path, "application/json", bytes.NewReader(data))
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		data, err = io.ReadAll(response.Body)
		if err != nil {
			t.Fatal(err)
		}
		return response.StatusCode, data
	}
	source := analystSource{SessionID: "primary", Binding: ab}
	included := []analystSource{source, {SessionID: "secondary", Binding: bb}}
	query := analyst.Query{Kind: "endpoint", Value: "192.0.2.1", Types: []string{"Connection"}}
	status, data := call("/api/analyst/catalogue", catalogueRequest{Sources: included, Query: query})
	if status != 200 {
		t.Fatalf("search %d %s", status, data)
	}
	var catalogue analyst.Catalogue
	if err := json.Unmarshal(data, &catalogue); err != nil {
		t.Fatal(err)
	}
	document := analyst.Document{Kind: "query", Title: "Retained peer query", Binding: ab, IncludedSources: included, Query: &query, CatalogueSnapshotSHA256: catalogue.SnapshotSHA256, Review: "draft", References: []analyst.Reference{catalogue.Occurrences[0].Reference}}
	status, data = call("/api/analyst/workspace", analyst.WorkspaceRequest{Source: source, Document: &document})
	if status != 200 {
		t.Fatalf("save %d %s", status, data)
	}
	if err := json.Unmarshal(data, &document); err != nil {
		t.Fatal(err)
	}
	document.Review = "reviewed"
	document.Reviewer = "explicit human reviewer"
	status, data = call("/api/analyst/workspace", analyst.WorkspaceRequest{Source: source, Document: &document, ExpectedRevision: 1})
	if status != 200 {
		t.Fatalf("review %d %s", status, data)
	}
	api.Close()
	api = newAPI()
	status, data = call("/api/analyst/workspace", analyst.WorkspaceRequest{Source: source})
	if status != 200 {
		t.Fatalf("restart load %d %s", status, data)
	}
	var workspace analyst.Workspace
	if err := json.Unmarshal(data, &workspace); err != nil {
		t.Fatal(err)
	}
	if len(workspace.Documents) != 1 || workspace.Documents[0].Review != "reviewed" || workspace.Documents[0].Revision != 2 || len(workspace.Documents[0].IncludedSources) != 2 {
		t.Fatalf("lost persisted report %s", data)
	}
	manager.mu.Lock()
	manager.sessions["secondary"].IP = "192.0.2.99"
	manager.mu.Unlock()
	status, data = call("/api/analyst/workspace", analyst.WorkspaceRequest{Source: source})
	if status < 400 || strings.Contains(string(data), "Retained peer query") {
		t.Fatalf("revoked secondary source metadata leaked: %d %s", status, data)
	}
}
