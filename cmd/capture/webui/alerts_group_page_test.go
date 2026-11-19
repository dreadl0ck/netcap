package webui

import (
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/dreadl0ck/netcap/types"
	"github.com/gogo/protobuf/proto"
)

func TestGroupedSummaryBoundsSamplesAndPreservesExactTimes(t *testing.T) {
	group := GroupedAlert{GroupID: "group", RuleName: "large", Count: 10000, FirstSeen: 1700000000000000001, LastSeen: 1700000000000000003, SampleAlerts: []AlertResponse{{MatchedRecord: strings.Repeat("x", 9<<20)}}}
	for index := range 10000 {
		group.UniqueSrcIPs = append(group.UniqueSrcIPs, fmt.Sprintf("host-%05d", index))
	}
	rows, err := groupedAlertPageRows([]GroupedAlert{group})
	if err != nil {
		t.Fatal(err)
	}
	wire, err := json.Marshal(rows)
	if err != nil || len(wire) > 8192 {
		t.Fatal("group summary retained its members", len(wire), err)
	}
	if !strings.Contains(string(wire), `"firstSeen":1700000000000000001`) || rows[0]["uniqueSrcIPsTotal"] != 10000 || rows[0]["membersPaged"] != true {
		t.Fatal("group summary changed counts or timestamps", string(wire))
	}
	if len(rows[0]["sampleAlerts"].([]any)) != 0 || len(rows[0]["uniqueSrcIPs"].([]any)) != 10 {
		t.Fatal("unbounded group preview")
	}
	digest := rows[0]["groupDataSHA256"]
	group.UniqueSrcIPs[len(group.UniqueSrcIPs)-1] = "changed-outside-preview"
	changed, err := groupedAlertPageRows([]GroupedAlert{group})
	if err != nil || changed[0]["groupDataSHA256"] == digest {
		t.Fatal("hidden member change did not change generation seed", err)
	}
}

func TestGroupedAlertPagesBreakSortTiesBySeverity(t *testing.T) {
	dir := t.TempDir()
	writeTimelineAuditFile(t, dir, "Alert", types.Type_NC_Alert, []proto.Message{
		&types.Alert{RuleName: "same", Severity: "info", Timestamp: 1000000},
		&types.Alert{RuleName: "same", Severity: "notice", Timestamp: 1000000},
	})
	s := &Server{outDir: dir}
	for _, field := range []string{"count", "firstSeen", "lastSeen", "severity"} {
		for _, direction := range []string{"asc", "desc"} {
			for offset, severity := range []string{"info", "notice"} {
				if direction == "desc" {
					offset = 1 - offset
				}
				url := fmt.Sprintf("/api/alerts/grouped?sortBy=%s&sort=%s&limit=1&offset=%d", field, direction, offset)
				w := httptest.NewRecorder()
				s.handleGroupedAlerts(w, httptest.NewRequest("GET", url, nil))
				var page GroupedAlertsResponse
				if err := json.Unmarshal(w.Body.Bytes(), &page); err != nil || w.Code != 200 || len(page.Groups) != 1 || page.Groups[0].Severity != severity {
					t.Fatalf("%s: expected %s, got %d %s (%v)", url, severity, w.Code, w.Body, err)
				}
			}
		}
	}
}

func TestGroupedSearchFindsHiddenMembersAndMemberPagesAreComplete(t *testing.T) {
	dir := t.TempDir()
	var alerts []proto.Message
	for index := range 31 {
		alerts = append(alerts, &types.Alert{RuleName: "one", Severity: "info", SrcIP: fmt.Sprintf("host-%03d", index), Timestamp: int64(index + 1)})
	}
	alerts = append(alerts, &types.Alert{RuleName: "one", Severity: "high", SrcIP: "other", Timestamp: 100})
	writeTimelineAuditFile(t, dir, "Alert", types.Type(types.Type_value["NC_Alert"]), alerts)
	s := &Server{outDir: dir}
	w := httptest.NewRecorder()
	s.handleGroupedAlerts(w, httptest.NewRequest("GET", "/api/alerts/grouped?mcpPage=true&pageSearch=host-030", nil))
	var grouped struct {
		Groups     []GroupedAlert `json:"groups"`
		GroupCount int            `json:"groupCount"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &grouped); err != nil || w.Code != 200 || grouped.GroupCount != 1 || len(grouped.Groups) != 1 {
		t.Fatal("hidden member search was lost", w.Code, w.Body.String(), err)
	}
	groupID := grouped.Groups[0].GroupID
	offset := 0
	seen := map[string]bool{}
	generation := ""
	for {
		w := httptest.NewRecorder()
		s.handleAlerts(w, httptest.NewRequest("GET", fmt.Sprintf("/api/alerts?mcpPage=true&groupId=%s&pageLimit=7&pageOffset=%d&pageGeneration=%s", groupID, offset, generation), nil))
		var page struct {
			Alerts     []AlertResponse `json:"alerts"`
			Total      int             `json:"totalCount"`
			Next       int             `json:"next_offset"`
			More       bool            `json:"has_more"`
			Generation string          `json:"generation"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &page); err != nil || w.Code != 200 || page.Total != 31 {
			t.Fatal(w.Code, w.Body.String(), err)
		}
		for _, alert := range page.Alerts {
			if alert.Severity != "info" || seen[alert.SrcIP] {
				t.Fatal("group member isolation or paging failed", alert)
			}
			seen[alert.SrcIP] = true
		}
		if !page.More {
			break
		}
		if page.Next <= offset {
			t.Fatal("member page did not advance")
		}
		offset, generation = page.Next, page.Generation
	}
	if len(seen) != 31 {
		t.Fatal("member pages lost alerts", len(seen))
	}
}
