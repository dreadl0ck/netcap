package webui

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/dreadl0ck/netcap/internal/rules"
	"github.com/dreadl0ck/netcap/types"
	"github.com/gogo/protobuf/proto"
)

func TestGroupedSummaryBoundsSamplesAndPreservesExactTimes(t *testing.T) {
	group := GroupedAlert{GroupID: "group", RuleName: "large", Count: 10000, FirstSeen: 1700000000001, LastSeen: 1700000000003, SampleAlerts: []AlertResponse{{MatchedRecord: strings.Repeat("x", 9<<20)}}}
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
	if !strings.Contains(string(wire), `"firstSeen":1700000000001`) || rows[0]["uniqueSrcIPsTotal"] != 10000 || rows[0]["membersPaged"] != true {
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

func TestMCPGroupedAlertsCountBeyondPreviewAndInvalidateHiddenEdits(t *testing.T) {
	dir := t.TempDir()
	const distinct = 300
	alerts := make([]proto.Message, 0, distinct+2)
	for i := range distinct + 1 {
		alerts = append(alerts, &types.Alert{
			Timestamp: int64(i+1) * 1000000, RuleName: "inventory", Severity: "info", Tags: []string{rules.InventoryTag},
			SrcIP: fmt.Sprintf("10.0.%d.%d", (i%distinct)/250, (i%distinct)%250), DstIP: "192.0.2.1",
		})
	}
	alerts = append(alerts, &types.Alert{RuleName: "another", Severity: "info"})
	writeTimelineAuditFile(t, dir, "Alert", types.Type_NC_Alert, alerts)
	s := &Server{outDir: dir}
	get := func(query string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		s.handleGroupedAlerts(w, httptest.NewRequest("GET", "/api/alerts/grouped?kind=all&mcpPage=true&"+query, nil))
		return w
	}
	w := get("pageLimit=2")
	var page struct {
		Groups []struct {
			GroupedAlert
			UniqueSrcIPsTotal int
		}
		Generation string
	}
	if err := json.Unmarshal(w.Body.Bytes(), &page); err != nil || w.Code != http.StatusOK || len(page.Groups) != 2 || page.Generation == "" {
		t.Fatalf("expected two MCP groups: %d %s (%v)", w.Code, w.Body, err)
	}
	g := page.Groups[0]
	if g.RuleName != "inventory" {
		g = page.Groups[1]
	}
	if g.UniqueSrcIPsTotal != distinct || g.Count != distinct+1 || len(g.UniqueSrcIPs) != 10 || g.UniqueValuesTruncated {
		t.Fatalf("expected exact distinct total and bounded preview: %+v", g)
	}
	query := "pageLimit=1&pageOffset=1&pageGeneration=" + page.Generation
	if w = get(query); w.Code != http.StatusOK {
		t.Fatalf("unchanged pagination: %d %s", w.Code, w.Body)
	}
	// Change the last member's content, without touching totals, times, or the first five samples.
	alerts[distinct].(*types.Alert).Description = "edited hidden member"
	writeTimelineAuditFile(t, dir, "Alert", types.Type_NC_Alert, alerts)
	if w = get(query); w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "collection generation changed") {
		t.Fatalf("hidden member edit must invalidate pagination: %d %s", w.Code, w.Body)
	}
}

func TestExactGroupStateRefusesAdditionalUniqueValuesOverBudget(t *testing.T) {
	acc := newAlertGroups(32<<10, true)
	for i := 0; i < 1024; i++ {
		err := acc.add(AlertResponse{RuleName: "inventory", Kind: rules.KindInventory, SrcIP: fmt.Sprintf("host-%04d", i)}, "", "")
		if err == nil {
			continue
		}
		if !errors.Is(err, errAlertPageSourceLimit) || i <= maxGroupUniqueValues {
			t.Fatalf("unexpected failure at %d unique values: %v", i, err)
		}
		return
	}
	t.Fatal("exact summary did not honor the state budget")
}

func TestAlertStatsRefusesOversizedEncodedRecentRows(t *testing.T) {
	dir := t.TempDir()
	// Each protobuf frame fits; JSON escapes each control byte as six bytes.
	description := strings.Repeat("\x01", 768<<10)
	writeTimelineAuditFile(t, dir, "Alert", types.Type_NC_Alert, []proto.Message{
		&types.Alert{Description: description, Timestamp: 1_000_000},
		&types.Alert{Description: description, Timestamp: 2_000_000},
	})
	s := &Server{outDir: dir}
	w := httptest.NewRecorder()
	s.handleAlertStats(w, httptest.NewRequest("GET", "/api/alerts/stats", nil))
	var response map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil || w.Code != 413 || len(response) != 1 ||
		!strings.Contains(response["error"], "statistics response exceeds") {
		t.Fatalf("expected error-only encoded response refusal: status=%d bytes=%d err=%v", w.Code, w.Body.Len(), err)
	}
}

func TestAlertStatsRecentRowsPreserveResolutionAndMillisecondTies(t *testing.T) {
	dir := t.TempDir()
	rows := make([]proto.Message, 0, 12)
	for i := range 11 {
		rows = append(rows, &types.Alert{Timestamp: 1_000_000 + int64(i), RuleName: fmt.Sprintf("tie-%02d", i)})
	}
	rows = append(rows, &types.Alert{Timestamp: 2_000_000, RuleName: "newest"})
	writeTimelineAuditFile(t, dir, "Alert", types.Type_NC_Alert, rows)
	s := &Server{outDir: dir}
	id := alertResponse(rows[0].(*types.Alert)).AlertID
	if err := s.saveResolvedAlerts(dir, &ResolvedAlertsStore{Alerts: map[string]ResolvedAlert{
		id: {AlertID: id, ResolvedAt: 42},
	}}); err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	s.handleAlertStats(w, httptest.NewRequest("GET", "/api/alerts/stats", nil))
	var stats struct {
		TotalAlerts  int
		RecentAlerts []AlertResponse
	}
	if err := json.Unmarshal(w.Body.Bytes(), &stats); err != nil || w.Code != 200 || stats.TotalAlerts != 12 || len(stats.RecentAlerts) != 10 {
		t.Fatalf("unexpected statistics: %d %s (%v)", w.Code, w.Body, err)
	}
	if stats.RecentAlerts[0].RuleName != "newest" || !stats.RecentAlerts[1].Resolved || stats.RecentAlerts[1].ResolvedAt != 42 {
		t.Fatalf("newest or resolved alert was lost: %+v", stats.RecentAlerts[:2])
	}
	for i, alert := range stats.RecentAlerts[1:] {
		if alert.RuleName != fmt.Sprintf("tie-%02d", i) {
			t.Fatalf("unexpected tie order at %d: %s", i, alert.RuleName)
		}
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

func TestGroupedAlertPagesPreserveObservedPorts(t *testing.T) {
	dir := t.TempDir()
	writeTimelineAuditFile(t, dir, "Alert", types.Type_NC_Alert, []proto.Message{
		&types.Alert{RuleName: "ports", Severity: "info", SrcPort: "1234", DstPort: "443"},
		&types.Alert{RuleName: "ports", Severity: "info", SrcPort: "1234", MatchedRecord: `{"SrcPort":99,"DstPort":"80"}`},
		&types.Alert{RuleName: "ports", Severity: "info", MatchedRecord: `{"SrcPort":5678,"DstPort":443}`},
	})
	s := &Server{outDir: dir}
	w := httptest.NewRecorder()
	s.handleGroupedAlerts(w, httptest.NewRequest("GET", "/api/alerts/grouped?mcpPage=true", nil))
	var page struct {
		Groups []struct {
			UniqueSrcPorts, UniqueDstPorts           []string
			UniqueSrcPortsTotal, UniqueDstPortsTotal int
		}
	}
	if err := json.Unmarshal(w.Body.Bytes(), &page); err != nil || w.Code != 200 || len(page.Groups) != 1 {
		t.Fatalf("expected one group: %d %s (%v)", w.Code, w.Body, err)
	}
	g := page.Groups[0]
	if g.UniqueSrcPortsTotal != 2 || g.UniqueDstPortsTotal != 2 ||
		strings.Join(g.UniqueSrcPorts, ",") != "1234,5678" || strings.Join(g.UniqueDstPorts, ",") != "443,80" {
		t.Fatalf("unexpected grouped ports: %+v", g)
	}
}

func TestGroupedFileFindingsUseObservedRange(t *testing.T) {
	dir := t.TempDir()
	const firstNS, lastNS = int64(1700000000000000421), int64(1700000025342000999)
	writeTimelineAuditFile(t, dir, "Alert", types.Type_NC_Alert, []proto.Message{
		&types.Alert{RuleName: "files", Severity: "high", RecordType: "NC_File", Timestamp: firstNS,
			FirstSeen: firstNS, LastSeen: lastNS, Count: 7, SrcIP: "192.0.2.1", DstIP: "192.0.2.2"},
		&types.Alert{RuleName: "files", Severity: "high", Timestamp: firstNS + 1e9, SrcIP: "192.0.2.1", DstIP: "192.0.2.2"},
	})
	w := httptest.NewRecorder()
	(&Server{outDir: dir}).handleGroupedAlerts(w, httptest.NewRequest("GET", "/api/alerts/grouped?mcpPage=true", nil))
	var page GroupedAlertsResponse
	if err := json.Unmarshal(w.Body.Bytes(), &page); err != nil || w.Code != 200 || len(page.Groups) != 1 {
		t.Fatalf("expected one group: %d %s (%v)", w.Code, w.Body, err)
	}
	group := page.Groups[0]
	if group.Count != 2 || group.FirstSeen != firstNS/1e6 || group.LastSeen != lastNS/1e6 {
		t.Fatalf("unexpected grouped range or row count: %+v", group)
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
