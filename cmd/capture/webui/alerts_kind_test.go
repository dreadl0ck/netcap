package webui

import (
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/gogo/protobuf/proto"

	"github.com/dreadl0ck/netcap/internal/rules"
	"github.com/dreadl0ck/netcap/types"
)

// Inventory alerts (SMB seen, Apache seen) outnumbered findings several
// times over on the evaluation corpus; alert views now list findings unless
// asked for inventory.
func TestAlertViewsDefaultToFindings(t *testing.T) {
	dir := t.TempDir()
	writeTimelineAuditFile(t, dir, "Alert", types.Type_NC_Alert, []proto.Message{
		&types.Alert{Timestamp: 1, RuleName: "C2", Severity: "high"},
		&types.Alert{Timestamp: 2, RuleName: "SMB", Severity: "info", Tags: []string{rules.InventoryTag}},
		&types.Alert{Timestamp: 3, RuleName: "Apache", Severity: "info", RuleExpression: "ServerName != \"\""},
		&types.Alert{Timestamp: 4, RuleName: "Beacon", Severity: "info", Tags: []string{rules.FindingTag}},
		&types.Alert{Timestamp: 5, RuleName: "policy.cleartext-service", Severity: "info", RecordType: "NetworkDetection"},
	})
	s := &Server{outDir: dir}
	list := func(query string) AlertsResponse {
		w := httptest.NewRecorder()
		s.handleAlerts(w, httptest.NewRequest("GET", "/api/alerts"+query, nil))
		var page AlertsResponse
		_ = json.Unmarshal(w.Body.Bytes(), &page)
		return page
	}
	if page := list(""); page.TotalCount != 2 || page.Alerts[1].RuleName != "C2" || page.Alerts[0].Kind != "finding" {
		t.Fatalf("default: %+v", page)
	}
	if page := list("?kind=inventory"); page.TotalCount != 3 || page.Alerts[0].Kind != "inventory" {
		t.Fatalf("inventory: %+v", page)
	}
	if page := list("?kind=all"); page.TotalCount != 5 {
		t.Fatalf("all: %+v", page)
	}
	w := httptest.NewRecorder()
	s.handleAlerts(w, httptest.NewRequest("GET", "/api/alerts?kind=nope", nil))
	if w.Code != 400 {
		t.Fatalf("bad kind: %d", w.Code)
	}
	w = httptest.NewRecorder()
	s.handleGroupedAlerts(w, httptest.NewRequest("GET", "/api/alerts/grouped?mcpPage=true&pageLimit=10", nil))
	var grouped struct{ GroupCount int }
	if json.Unmarshal(w.Body.Bytes(), &grouped) != nil || grouped.GroupCount != 2 {
		t.Fatalf("grouped: %s", w.Body)
	}
	w = httptest.NewRecorder()
	s.handleAlertStats(w, httptest.NewRequest("GET", "/api/alerts/stats", nil))
	var stats struct {
		TotalAlerts int
		ByKind      map[string]int
	}
	if json.Unmarshal(w.Body.Bytes(), &stats) != nil || stats.TotalAlerts != 2 || stats.ByKind["inventory"] != 3 || stats.ByKind["finding"] != 2 {
		t.Fatalf("stats: %s", w.Body)
	}
}
