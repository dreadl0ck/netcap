package webui

import (
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/dreadl0ck/netcap/internal/evidencelink"
	"github.com/dreadl0ck/netcap/internal/rules"
	"github.com/dreadl0ck/netcap/types"
	"github.com/gogo/protobuf/proto"
)

func TestRuleReplayPublishesRelatedEvidenceWithoutAggregateCount(t *testing.T) {
	dir := t.TempDir()
	const client = "192.0.2.1"
	writeTimelineAuditFile(t, dir, "Connection", types.Type_NC_Connection, []proto.Message{
		&types.Connection{TimestampFirst: 1e9, TimestampLast: 3e9, TransportProto: "TCP", NetworkScope: "fixture-scope", SrcIP: client, DstIP: "192.0.2.2", SrcPort: "40001", DstPort: "80", CommunityID: "1:parent"},
		&types.Connection{TimestampFirst: 3e9, TimestampLast: 6e9, TransportProto: "TCP", NetworkScope: "fixture-scope", SrcIP: client, DstIP: "192.0.2.3", SrcPort: "40002", DstPort: "80", CommunityID: "1:child"},
	})
	writeTimelineAuditFile(t, dir, "HTTP", types.Type_NC_HTTP, []proto.Message{
		&types.HTTP{Timestamp: 2e9, CommunityID: "1:parent", SrcIP: client, DstIP: "192.0.2.2", SrcPort: 40001, DstPort: 80, Method: "GET", URL: "/", Host: "parent.example", StatusCode: 200},
		&types.HTTP{Timestamp: 5e9, CommunityID: "1:child", SrcIP: client, DstIP: "192.0.2.3", SrcPort: 40002, DstPort: 80, Method: "GET", URL: "/file", Host: "child.example", Referer: "http://parent.example/", StatusCode: 200},
	})
	s := &Server{outDir: dir}
	result, err := s.replayManualRules(dir, []*rules.Rule{{Name: "fixture", Type: "HTTP", Expression: `Host == "child.example"`, Severity: "medium", Enabled: true}}, nil)
	if err != nil || len(result) != 1 || !result[0].Success || result[0].AlertsCount != 1 {
		t.Fatalf("rule replay: %+v (%v)", result, err)
	}
	w := httptest.NewRecorder()
	s.handleAlerts(w, httptest.NewRequest("GET", "/api/alerts?mcpPage=true", nil))
	var payload struct{ Alerts []AlertResponse }
	if err := json.Unmarshal(w.Body.Bytes(), &payload); err != nil || w.Code != 200 || len(payload.Alerts) != 1 {
		t.Fatalf("alert page: %s (%v)", w.Body, err)
	}
	alert := payload.Alerts[0]
	if alert.Count != 0 || len(alert.Examples) != 1 {
		t.Fatalf("missing evidence on a single-match alert: %+v", alert)
	}
	var linked evidencelink.RelatedEvidence
	if err := json.Unmarshal([]byte(alert.Examples[0]), &linked); err != nil || linked.Relationship != "http-referrer" || linked.Name != "parent.example" || linked.Record.Ordinal != 0 {
		t.Fatalf("HTTP link with wrong provenance: %+v (%v)", linked, err)
	}
}
