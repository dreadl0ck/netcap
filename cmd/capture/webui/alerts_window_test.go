package webui

import (
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"testing"

	"github.com/gogo/protobuf/proto"

	"github.com/dreadl0ck/netcap/types"
)

// The WebUI alert list and grouped view read the whole audit into memory and
// sorted it; they now stream and keep only the requested window.
func TestAlertListStreamsAWindow(t *testing.T) {
	dir := t.TempDir()
	rows := make([]proto.Message, 0, 3000)
	for i := range 3000 {
		severity := "low"
		if i%3 == 0 {
			severity = "high"
		}
		rows = append(rows, &types.Alert{Timestamp: int64((i*7919)%3000) * 1_000_000_000, RuleName: "r", Severity: severity, SrcIP: fmt.Sprintf("10.0.%d.%d", i/250, i%250)})
	}
	writeTimelineAuditFile(t, dir, "Alert", types.Type_NC_Alert, rows)
	s := &Server{outDir: dir}
	get := func(query string) (AlertsResponse, int) {
		w := httptest.NewRecorder()
		s.handleAlerts(w, httptest.NewRequest("GET", "/api/alerts?"+query, nil))
		var page AlertsResponse
		_ = json.Unmarshal(w.Body.Bytes(), &page)
		return page, w.Code
	}
	page, code := get("groupId=r-high&limit=5&offset=10")
	if code != 200 || page.TotalCount != 1000 || len(page.Alerts) != 5 {
		t.Fatalf("%d total %d len %d", code, page.TotalCount, len(page.Alerts))
	}
	for i, alert := range page.Alerts {
		if alert.Severity != "high" || i > 0 && alert.Timestamp > page.Alerts[i-1].Timestamp {
			t.Fatalf("filter or order broken at %d: %+v", i, alert)
		}
	}
	all, _ := get("groupId=r-high&limit=1000")
	if all.Alerts[10].AlertID != page.Alerts[0].AlertID {
		t.Fatal("offset window differs from the full ordering")
	}
	asc, _ := get("limit=3&sort=asc")
	if asc.Alerts[0].Timestamp >= asc.Alerts[1].Timestamp || asc.Alerts[1].Timestamp >= asc.Alerts[2].Timestamp {
		t.Fatalf("ascending: %+v", asc.Alerts)
	}
	if _, code := get(fmt.Sprintf("limit=10&offset=%d", maxAlertListWindow)); code != 400 {
		t.Fatalf("window above the bound: %d", code)
	}

	w := httptest.NewRecorder()
	s.handleGroupedAlerts(w, httptest.NewRequest("GET", "/api/alerts/grouped", nil))
	var grouped GroupedAlertsResponse
	if err := json.Unmarshal(w.Body.Bytes(), &grouped); err != nil || grouped.TotalCount != 3000 || len(grouped.Groups) != 2 {
		t.Fatalf("grouped: %d %v %+v", w.Code, err, grouped.GroupCount)
	}
	for _, group := range grouped.Groups {
		if len(group.UniqueSrcIPs) != maxGroupUniqueValues || !group.UniqueValuesTruncated {
			t.Fatalf("unique sources %d truncated %v", len(group.UniqueSrcIPs), group.UniqueValuesTruncated)
		}
	}

	if err := s.saveResolvedAlerts(dir, &ResolvedAlertsStore{Groups: map[string]ResolvedGroup{"r-high": {Through: 1 << 62}}}); err != nil {
		t.Fatal(err)
	}
	w = httptest.NewRecorder()
	s.handleGroupedAlerts(w, httptest.NewRequest("GET", "/api/alerts/grouped?hideResolved=true&limit=1", nil))
	grouped = GroupedAlertsResponse{}
	if err := json.Unmarshal(w.Body.Bytes(), &grouped); err != nil || grouped.GroupCount != 1 || grouped.Groups[0].GroupID != "r-low" {
		t.Fatalf("hideResolved: %s", w.Body)
	}
}
