package webui

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dreadl0ck/netcap/internal/delimited"
	"github.com/dreadl0ck/netcap/internal/evidence"
	"github.com/dreadl0ck/netcap/internal/rules"
	"github.com/dreadl0ck/netcap/types"
)

func offlineTestRequest(t *testing.T, body any) *http.Request {
	t.Helper()
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	return httptest.NewRequest(http.MethodPost, "/api/rules/offline/execute", bytes.NewReader(b))
}

func enabledOfflineExample() string {
	return strings.ReplaceAll(offlineExampleYAML, "enabled: false", "enabled: true")
}

func TestOfflineValidate(t *testing.T) {
	s := &Server{}
	for _, test := range []struct {
		name, body string
		code       int
	}{
		{"valid", string(mustOfflineJSON(t, map[string]string{"yaml": enabledOfflineExample()})), 200},
		{"disabled", string(mustOfflineJSON(t, map[string]string{"yaml": offlineExampleYAML})), 400},
		{"legacy", `{"yaml":"rules: []"}`, 400},
		{"unknown", `{"yaml":"x", "path":"/etc/pack.yaml"}`, 400},
		{"trailing", `{"yaml":"x"} {}`, 400},
		{"oversize", `{"yaml":"` + strings.Repeat("a", 1<<20) + `"}`, 400},
	} {
		t.Run(test.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			s.handleOfflineValidate(w, httptest.NewRequest(http.MethodPost, "/api/rules/offline/validate", strings.NewReader(test.body)))
			if w.Code != test.code {
				t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
			}
			var result struct {
				Valid  bool  `json:"valid"`
				Errors []any `json:"errors"`
			}
			if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
				t.Fatal(err)
			}
			if result.Valid != (test.code == 200) || (test.code != 200 && len(result.Errors) == 0) {
				t.Fatalf("validation=%s", w.Body.String())
			}
		})
	}
}

func mustOfflineJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestOfflineExecuteRejectsActiveAndUnknownCapture(t *testing.T) {
	for _, test := range []struct {
		name, input     string
		live, completed bool
		code            int
	}{
		{"active", "/fixture.pcap", false, false, 409}, {"live", "/fixture.pcap", true, true, 409}, {"unknown", "/other.pcap", false, true, 404},
	} {
		t.Run(test.name, func(t *testing.T) {
			s := &Server{outDir: t.TempDir(), baseOutDir: t.TempDir(), inputFiles: []string{"/fixture.pcap"}, completedFiles: map[string]bool{"/fixture.pcap": test.completed}, isLiveMode: test.live}
			w := httptest.NewRecorder()
			s.handleOfflineExecute(w, offlineTestRequest(t, offlinePackRequest{YAML: enabledOfflineExample(), InputFile: test.input}))
			if w.Code != test.code {
				t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
			}
		})
	}
}

func TestOfflineSessionOwnership(t *testing.T) {
	manager := NewSessionManager(10, 60, 10)
	manager.sessions["private"] = &SessionInfo{IP: "192.0.2.20", Status: StatusCompleted, OutputDir: t.TempDir()}
	s := &Server{isServiceMode: true, sessionManager: manager}
	r := httptest.NewRequest(http.MethodGet, "/api/rules/offline/evaluations?sessionId=private", nil)
	r.RemoteAddr = "192.0.2.21:1234"
	w := httptest.NewRecorder()
	s.handleOfflineEvaluations(w, r)
	if w.Code != 403 {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
}

func TestOfflineOutputLeaseBlocksMutations(t *testing.T) {
	dir := t.TempDir()
	lease, err := rules.AcquireOfflineLease(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Close()
	s := &Server{outDir: dir, baseOutDir: dir, inputFiles: []string{"/fixture.pcap"}, completedFiles: map[string]bool{"/fixture.pcap": true}, fileOutputDirs: map[string]string{"/fixture.pcap": dir}}
	for _, test := range []struct {
		name    string
		handler http.HandlerFunc
		body    any
	}{
		{"clear", s.handleClearAlerts, map[string]string{}},
		{"reanalyze", s.handleReanalyze, map[string]string{"inputFile": "/fixture.pcap"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			test.handler(w, offlineTestRequest(t, test.body))
			if w.Code != 409 {
				t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
			}
		})
	}
	if !s.completedFiles["/fixture.pcap"] {
		t.Fatal("busy reanalysis changed completion state")
	}
}

func TestAlertsReaderErrorsAreNotEmptySuccess(t *testing.T) {
	for _, corrupt := range []bool{false, true} {
		dir := t.TempDir()
		if corrupt {
			if err := os.WriteFile(filepath.Join(dir, "Alert.ncap.gz"), []byte("corrupt"), 0600); err != nil {
				t.Fatal(err)
			}
		}
		s := &Server{outDir: dir}
		for _, handler := range []http.HandlerFunc{s.handleAlerts, s.handleAlertStats, s.handleGroupedAlerts} {
			w := httptest.NewRecorder()
			handler(w, httptest.NewRequest(http.MethodGet, "/api/alerts", nil))
			want := 200
			if corrupt {
				want = 500
			}
			if w.Code != want {
				t.Fatalf("corrupt=%v status=%d body=%s", corrupt, w.Code, w.Body.String())
			}
		}
	}
}

func offlineSyntheticCapture(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	manifest := evidence.CaptureManifest{Version: 1, RunID: "fixture-run", Status: "complete", ConfigSHA256: strings.Repeat("a", 64), CommunityScopes: &evidence.ScopeLedger{Schema: 1, Complete: true, Entries: []evidence.CommunityScope{{CommunityID: "1:fixture", Scope: evidence.FlowScope{Sensor: "local"}}}}}
	for name, value := range map[string]any{"capture-manifest.json": manifest, rules.OfflineReadyFile: rules.OfflineReadyMarker{Version: 1, RunID: manifest.RunID}} {
		if err := os.WriteFile(filepath.Join(dir, name), mustOfflineJSON(t, value), 0600); err != nil {
			t.Fatal(err)
		}
	}
	f, err := os.Create(filepath.Join(dir, "TCP.ncap.gz"))
	if err != nil {
		t.Fatal(err)
	}
	gz := gzip.NewWriter(f)
	writer := delimited.NewWriter(gz)
	if err := writer.PutProto(&types.Header{Type: types.Type_NC_TCP}); err != nil {
		t.Fatal(err)
	}
	for _, timestamp := range []int64{1_000_000_000, 2_000_000_000} {
		if err := writer.PutProto(&types.TCP{Timestamp: timestamp, SrcIP: "192.0.2.1", DstIP: "192.0.2.2", DstPort: 443, CommunityID: "1:fixture"}); err != nil {
			t.Fatal(err)
		}
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestOfflineExecuteSyntheticCaptureAndHistory(t *testing.T) {
	dir := offlineSyntheticCapture(t)
	s := &Server{outDir: dir, baseOutDir: dir, inputFiles: []string{"/fixture.pcap"}, completedFiles: map[string]bool{"/fixture.pcap": true}}
	yaml := strings.ReplaceAll(strings.ReplaceAll(offlineExampleYAML, "enabled: false", "enabled: true"), "count: 10", "count: 2")
	yaml = strings.ReplaceAll(yaml, "group_by: [SrcIP]", "group_by: [SrcIP, DstPort]")
	w := httptest.NewRecorder()
	s.handleOfflineExecute(w, offlineTestRequest(t, offlinePackRequest{YAML: yaml, InputFile: "/fixture.pcap"}))
	if w.Code != 200 {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	var result struct {
		Report rules.OfflineReport `json:"report"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Report.Status != "complete" || result.Report.CommittedAlerts != 1 {
		t.Fatalf("report=%+v", result.Report)
	}
	alerts, err := s.readAlertsFromFile(filepath.Join(dir, "Alert.ncap.gz"))
	if err != nil {
		t.Fatal(err)
	}
	if len(alerts) != 1 || alerts[0].GroupedEvaluation == nil || alerts[0].GroupedEvaluation.Count != 2 || alerts[0].AlertID != alerts[0].GroupedEvaluation.EventID {
		t.Fatalf("alerts=%+v", alerts)
	}
	if group := alerts[0].GroupedEvaluation.Group; group["SrcIP"] != "192.0.2.1" || !validOfflineGroupValue(group["DstPort"]) {
		t.Fatalf("numeric group metadata lost: %+v", group)
	}
	w = httptest.NewRecorder()
	s.handleAlerts(w, httptest.NewRequest(http.MethodGet, "/api/alerts?inputFile=/fixture.pcap", nil))
	var apiAlerts AlertsResponse
	if err := json.Unmarshal(w.Body.Bytes(), &apiAlerts); err != nil {
		t.Fatal(err)
	}
	if w.Code != 200 || len(apiAlerts.Alerts) != 1 || apiAlerts.Alerts[0].GroupedEvaluation == nil {
		t.Fatalf("alert API=%d %s", w.Code, w.Body.String())
	}
	metadata := apiAlerts.Alerts[0].GroupedEvaluation
	port, ok := metadata.Group["DstPort"].(map[string]any)
	if !ok || port["type"] != "int32" || port["value"] != "443" || apiAlerts.Alerts[0].AlertID != metadata.EventID || apiAlerts.Alerts[0].AlertID != alerts[0].AlertID {
		t.Fatalf("serialized numeric metadata or stable ID lost: %s", w.Body.String())
	}
	w = httptest.NewRecorder()
	s.handleGroupedAlerts(w, httptest.NewRequest(http.MethodGet, "/api/alerts/grouped?inputFile=/fixture.pcap", nil))
	var grouped GroupedAlertsResponse
	if err := json.Unmarshal(w.Body.Bytes(), &grouped); err != nil {
		t.Fatal(err)
	}
	if w.Code != 200 || len(grouped.Groups) != 1 || len(grouped.Groups[0].SampleAlerts) != 1 {
		t.Fatalf("grouped alert API=%d %s", w.Code, w.Body.String())
	}
	sample := grouped.Groups[0].SampleAlerts[0]
	if sample.GroupedEvaluation == nil || sample.AlertID != metadata.EventID || !validOfflineGroupValue(sample.GroupedEvaluation.Group["DstPort"]) {
		t.Fatalf("browser grouped-alert payload lost numeric metadata: %s", w.Body.String())
	}
	var record types.TCP
	if err := json.Unmarshal([]byte(alerts[0].MatchedRecord), &record); err != nil || record.DstPort != 443 {
		t.Fatalf("matched record changed: %s", alerts[0].MatchedRecord)
	}
	w = httptest.NewRecorder()
	s.handleOfflineEvaluations(w, httptest.NewRequest(http.MethodGet, "/api/rules/offline/evaluations?inputFile=/fixture.pcap", nil))
	if w.Code != 200 || !strings.Contains(w.Body.String(), result.Report.ID) {
		t.Fatalf("history=%d %s", w.Code, w.Body.String())
	}
}

func TestOfflineAlertMetadataVersionAndLegacyIdentity(t *testing.T) {
	legacy := &types.Alert{Timestamp: 1_000_000, RuleName: "legacy", SrcIP: "a", DstIP: "b", MatchedRecord: `{"raw":true}`}
	before := alertResponse(legacy)
	for _, notes := range []string{`{"other":{"version":1}}`, `{"netcapOffline":{"version":2}}`, `broken`} {
		legacy.Notes = notes
		after := alertResponse(legacy)
		if after.GroupedEvaluation != nil || after.AlertID != before.AlertID || after.MatchedRecord != before.MatchedRecord {
			t.Fatalf("legacy projection changed: %+v", after)
		}
	}
}

func TestOfflineAlertMetadataIntegerGroups(t *testing.T) {
	for _, test := range []struct {
		typ, value string
		valid      bool
	}{
		{"int", "80", true}, {"uint", "80", true},
		{"int8", "-128", true}, {"int8", "127", true}, {"int8", "128", false}, {"int8", "-129", false},
		{"int16", "-32768", true}, {"int16", "32768", false},
		{"int32", "80", true}, {"int32", "2147483648", false},
		{"int64", "-9223372036854775808", true}, {"int64", "9223372036854775808", false},
		{"uint8", "255", true}, {"uint8", "256", false},
		{"uint16", "65535", true}, {"uint16", "65536", false},
		{"uint32", "4294967295", true}, {"uint32", "4294967296", false},
		{"uint64", "18446744073709551615", true}, {"uint64", "18446744073709551616", false},
		{"uint64", "-1", false}, {"float64", "80", false}, {"float32", "80.5", false},
		{"unknown", "80", false}, {"int32", "80.0", false}, {"int32", "1e2", false},
		{"int32", "+80", false}, {"int32", "080", false}, {"int32", " 80", false}, {"int32", "", false},
	} {
		t.Run(test.typ+"/"+test.value, func(t *testing.T) {
			metadata := rules.OfflineAlertMetadata{Version: 1, EventID: strings.Repeat("a", 64), RunID: "run", RuleID: "rule", Count: 2, First: 1, Last: 2, Group: map[string]any{"SrcIP": "192.0.2.1", "DstPort": map[string]any{"type": test.typ, "value": test.value}}}
			alert := &types.Alert{RuleName: "test", Notes: string(mustOfflineJSON(t, map[string]any{"netcapOffline": metadata}))}
			response := alertResponse(alert)
			if (response.GroupedEvaluation != nil) != test.valid {
				t.Fatalf("valid=%v response=%+v", test.valid, response)
			}
			if test.valid && response.AlertID != metadata.EventID {
				t.Fatalf("stable ID fell back: %s", response.AlertID)
			}
			if !test.valid && response.AlertID == metadata.EventID {
				t.Fatal("invalid metadata replaced the legacy ID")
			}
		})
	}
	for _, value := range []any{80.0, nil, true, map[string]any{"type": "int32", "value": 80}, map[string]any{"type": "int32", "value": "80", "extra": true}} {
		if validOfflineGroupValue(value) {
			t.Fatalf("accepted malformed group: %#v", value)
		}
	}
	if !validOfflineGroupValue("192.0.2.1") {
		t.Fatal("string group rejected")
	}
}

func TestOfflineExecutePartialAndCancelled(t *testing.T) {
	for _, cancelled := range []bool{false, true} {
		dir := offlineSyntheticCapture(t)
		s := &Server{outDir: dir, baseOutDir: dir, inputFiles: []string{"/fixture.pcap"}, completedFiles: map[string]bool{"/fixture.pcap": true}}
		yaml := strings.ReplaceAll(strings.ReplaceAll(offlineExampleYAML, "enabled: false", "enabled: true"), "type: TCP", "type: UDP")
		request := offlineTestRequest(t, offlinePackRequest{YAML: yaml, InputFile: "/fixture.pcap"})
		if cancelled {
			ctx, cancel := context.WithCancel(request.Context())
			cancel()
			request = request.WithContext(ctx)
		}
		w := httptest.NewRecorder()
		s.handleOfflineExecute(w, request)
		if cancelled {
			if w.Code != 422 || !strings.Contains(w.Body.String(), "context canceled") {
				t.Fatalf("cancelled=%d %s", w.Code, w.Body.String())
			}
		} else {
			var result struct {
				Report rules.OfflineReport `json:"report"`
			}
			if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
				t.Fatal(err)
			}
			if w.Code != 200 || result.Report.Status != "partial" || len(result.Report.Types) != 1 || !result.Report.Types[0].Missing {
				t.Fatalf("partial=%d %s", w.Code, w.Body.String())
			}
		}
	}
}

func TestOfflineEvaluationHistoryReadFailure(t *testing.T) {
	dir := t.TempDir()
	s := &Server{outDir: dir}
	w := httptest.NewRecorder()
	s.handleOfflineEvaluations(w, httptest.NewRequest(http.MethodGet, "/api/rules/offline/evaluations", nil))
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"evaluations":[]`) {
		t.Fatalf("missing history=%d %s", w.Code, w.Body.String())
	}
	if err := os.WriteFile(filepath.Join(dir, "rule-evaluations"), []byte("not a directory"), 0600); err != nil {
		t.Fatal(err)
	}
	w = httptest.NewRecorder()
	s.handleOfflineEvaluations(w, httptest.NewRequest(http.MethodGet, "/api/rules/offline/evaluations", nil))
	if w.Code != 500 {
		t.Fatalf("broken history=%d %s", w.Code, w.Body.String())
	}
}

func TestOfflineExactInputSelectionStatus(t *testing.T) {
	for _, test := range []struct {
		name, input                 string
		processing                  bool
		selectStatus, executeStatus int
	}{
		{"active", "/active.pcap", true, 400, 409},
		{"queued", "/queued.pcap", true, 400, 409},
		{"unknown", "/unknown.pcap", true, 404, 404},
	} {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			s := &Server{outDir: dir, baseOutDir: dir, activeInputFile: "/done.pcap", isProcessing: test.processing,
				inputFiles: []string{"/done.pcap", "/active.pcap", "/queued.pcap"}, completedFiles: map[string]bool{"/done.pcap": true},
				fileOutputDirs: map[string]string{"/done.pcap": dir}}
			w := httptest.NewRecorder()
			s.handleSetDirectory(w, offlineTestRequest(t, map[string]string{"inputFile": test.input}))
			if w.Code != test.selectStatus || s.activeInputFile != "/done.pcap" || s.outDir != dir {
				t.Fatalf("selection status=%d body=%s active=%s out=%s", w.Code, w.Body.String(), s.activeInputFile, s.outDir)
			}
			w = httptest.NewRecorder()
			s.handleOfflineExecute(w, offlineTestRequest(t, offlinePackRequest{YAML: enabledOfflineExample(), InputFile: test.input}))
			if w.Code != test.executeStatus {
				t.Fatalf("execute status=%d body=%s", w.Code, w.Body.String())
			}
		})
	}
}

func TestOfflineInProcessLeaseBlocksAllMutations(t *testing.T) {
	dir := t.TempDir()
	release, ok := leaseOfflineOutput(dir)
	if !ok {
		t.Fatal("fixture lease unavailable")
	}
	defer release()
	s := &Server{outDir: dir, baseOutDir: dir, inputFiles: []string{"/fixture.pcap"}, completedFiles: map[string]bool{"/fixture.pcap": true}, fileOutputDirs: map[string]string{"/fixture.pcap": dir}}
	for _, test := range []struct {
		name    string
		handler http.HandlerFunc
		body    any
	}{
		{"execute", s.handleOfflineExecute, offlinePackRequest{YAML: enabledOfflineExample(), InputFile: "/fixture.pcap"}},
		{"clear", s.handleClearAlerts, map[string]string{}},
		{"reanalyze", s.handleReanalyze, map[string]string{"inputFile": "/fixture.pcap"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			test.handler(w, offlineTestRequest(t, test.body))
			if w.Code != 409 || !strings.Contains(w.Body.String(), "Capture output is busy") {
				t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
			}
			if !s.completedFiles["/fixture.pcap"] {
				t.Fatal("busy mutation changed completion")
			}
		})
	}
}
