package webui

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/dreadl0ck/netcap/internal/artifactio"
	"github.com/dreadl0ck/netcap/internal/rules"
	"github.com/dreadl0ck/netcap/types"
	"github.com/gogo/protobuf/proto"
)

func TestManualRuleBatchPreservesPerRuleResults(t *testing.T) {
	dir := t.TempDir()
	writeTimelineAuditFilePlain(t, dir, "HTTP", types.Type_NC_HTTP, []proto.Message{
		&types.HTTP{Method: "GET"}, &types.HTTP{Method: "POST"},
	})
	selected := []*rules.Rule{
		{Name: "get", Type: "HTTP", Expression: `Method == "GET"`, Enabled: true},
		{Name: "invalid", Type: "HTTP", Expression: `Method ==`, Enabled: true},
		{Name: "post", Type: "HTTP", Expression: `Method == "POST"`, Enabled: true},
		{Name: "missing", Type: "DNS", Expression: `true`, Enabled: true},
	}
	results, err := (&Server{}).replayManualRules(dir, selected, nil)
	if err != nil || len(results) != 4 {
		t.Fatal(results, err)
	}
	for _, i := range []int{0, 2} {
		if r := results[i]; !r.Success || r.AlertsCount != 1 || r.RecordsRead != 2 {
			t.Fatalf("unexpected rule result: %+v", r)
		}
	}
	if results[1].Success || results[1].Error == "" || !results[3].Success || results[3].RecordsRead != 0 {
		t.Fatal(results)
	}
}

func TestExecuteAllRulesReportsPartialFailure(t *testing.T) {
	dir := t.TempDir()
	writeTimelineAuditFilePlain(t, dir, "HTTP", types.Type_NC_HTTP, []proto.Message{&types.HTTP{Method: "GET"}})
	s := &Server{outDir: dir, rulesConfig: &rules.Config{Rules: []*rules.Rule{
		{Name: "get", Type: "HTTP", Expression: `Method == "GET"`, Enabled: true},
		{Name: "invalid", Type: "HTTP", Expression: `Method ==`, Enabled: true},
	}}}
	w := httptest.NewRecorder()
	s.handleExecuteAllRules(w, httptest.NewRequest(http.MethodPost, "/api/rules/execute-all", nil))
	var result ExecuteAllRulesResponse
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &result) != nil || result.Success ||
		result.TotalAlerts != 1 || result.TotalRecords != 1 || len(result.RuleResults) != 2 ||
		!result.RuleResults[0].Success || result.RuleResults[1].Success || result.RuleResults[1].Error == "" {
		t.Fatalf("partial replay response: %d %s", w.Code, w.Body.String())
	}
}

func TestRuleAuditRejectsLinkedPreferredTrack(t *testing.T) {
	dir := t.TempDir()
	rows := []proto.Message{&types.HTTP{Method: "GET"}}
	writeTimelineAuditFilePlain(t, dir, "HTTP", types.Type_NC_HTTP, rows)
	linked := writeTimelineAuditFile(t, t.TempDir(), "HTTP", types.Type_NC_HTTP, rows)
	if err := os.Symlink(linked, filepath.Join(dir, "HTTP.ncap.gz")); err != nil {
		t.Fatal(err)
	}
	count, err := scanRuleAudit(dir, "HTTP", nil, nil, func(types.AuditRecord) error {
		t.Fatal("rule replay visited a record despite the rejected preferred input")
		return nil
	})
	if count != 0 || !errors.Is(err, artifactio.ErrPath) {
		t.Fatalf("linked preferred input: records=%d, err=%v", count, err)
	}
}

func TestRuleAuditRejectsMissingRecordBody(t *testing.T) {
	dir := t.TempDir()
	path := writeTimelineAuditFilePlain(t, dir, "HTTP", types.Type_NC_HTTP, []proto.Message{&types.HTTP{Method: "GET"}})
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.Write([]byte{8})
	if err := errors.Join(err, f.Close()); err != nil {
		t.Fatal(err)
	}
	count, err := scanRuleAudit(dir, "HTTP", nil, nil, func(types.AuditRecord) error { return nil })
	if count != 1 || !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatal(count, err)
	}
}

func TestManualRuleReplayStopsOnRequestOrShutdown(t *testing.T) {
	dir := t.TempDir()
	writeTimelineAuditFilePlain(t, dir, "HTTP", types.Type_NC_HTTP, []proto.Message{&types.HTTP{Method: "GET"}, &types.HTTP{Method: "GET"}})
	for _, shutdown := range []bool{false, true} {
		done := make(chan struct{})
		s, request := &Server{}, done
		if shutdown {
			s.shutdownChan, request = done, nil
		}
		count, err := scanRuleAudit(dir, "HTTP", request, s.shutdownChan, func(types.AuditRecord) error {
			close(done)
			return nil
		})
		if count != 1 || !errors.Is(err, errAnalysisStopping) {
			t.Fatalf("shutdown=%t: count=%d, err=%v", shutdown, count, err)
		}
		selected := []*rules.Rule{{Name: "get", Type: "HTTP", Expression: `Method == "GET"`, Enabled: true}}
		if results, err := s.replayManualRules(dir, selected, request); len(results) != 0 || !errors.Is(err, errAnalysisStopping) {
			t.Fatalf("shutdown=%t: canceled replay admitted: %v, %v", shutdown, results, err)
		}
	}
}
