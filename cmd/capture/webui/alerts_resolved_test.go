package webui

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/gogo/protobuf/proto"

	"github.com/dreadl0ck/netcap/types"
)

func groupResolutionRequest(t *testing.T, s *Server, path string, body map[string]string) {
	t.Helper()
	raw, _ := json.Marshal(body)
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", path, bytes.NewReader(raw))
	if path == "/api/alerts/resolve" {
		s.handleResolveAlert(w, r)
	} else {
		s.handleUnresolveAlert(w, r)
	}
	if w.Code != 200 {
		t.Fatalf("%s %v: %d %s", path, body, w.Code, w.Body)
	}
}

func groupResolvedCount(t *testing.T, s *Server, dir string) (int, int) {
	t.Helper()
	resolved, total := 0, 0
	err := s.walkAlertAudit(t.Context(), filepath.Join(dir, "Alert.ncap.gz"), 0, alertStatsScanRows, alertStatsFrameBytes, func(alert *types.Alert, store *ResolvedAlertsStore) error {
		total++
		if ok, _ := isAlertResolved(alert, alertResponse(alert).AlertID, store); ok {
			resolved++
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return resolved, total
}

// Resolving a group used to read every alert into memory, fail above
// 65,536 rows, and write one entry per alert, which pushed the file past the
// 4 MiB page limit and broke every alert view of the session.
func TestResolveLargeGroupStaysCompact(t *testing.T) {
	dir := t.TempDir()
	const n = 70_000
	rows := make([]proto.Message, 0, n)
	for i := range n {
		rows = append(rows, &types.Alert{Timestamp: int64(i), DetectedAt: 1_000 + int64(i), RuleName: "flood", Severity: "high", SrcIP: fmt.Sprintf("10.%d.%d.%d", i>>16, i>>8&255, i&255), RuleDigest: "d", MatchedRecordSHA256: fmt.Sprint(i)})
	}
	rows = append(rows, &types.Alert{Timestamp: 1, DetectedAt: 5, RuleName: "other", Severity: "low", RuleDigest: "d"})
	writeTimelineAuditFile(t, dir, "Alert", types.Type_NC_Alert, rows)
	s := &Server{outDir: dir}

	groupResolutionRequest(t, s, "/api/alerts/resolve", map[string]string{"groupId": "flood-high"})
	info, err := os.Stat(filepath.Join(dir, "resolved_alerts.json"))
	if err != nil || info.Size() > 4096 {
		t.Fatalf("resolution file %v %v", info, err)
	}
	stats := httptest.NewRecorder()
	s.handleAlertStats(stats, httptest.NewRequest("GET", "/api/alerts/stats", nil))
	if stats.Code != 200 {
		t.Fatalf("alert views fail after resolving: %d %s", stats.Code, stats.Body)
	}
	if resolved, total := groupResolvedCount(t, s, dir); resolved != n || total != n+1 {
		t.Fatalf("resolved %d of %d", resolved, total)
	}

	// Unresolving one alert of a resolved group keeps the rest resolved.
	first := alertResponse(rows[0].(*types.Alert)).AlertID
	groupResolutionRequest(t, s, "/api/alerts/unresolve", map[string]string{"alertId": first})
	if resolved, _ := groupResolvedCount(t, s, dir); resolved != n-1 {
		t.Fatalf("after one unresolve: %d", resolved)
	}
	groupResolutionRequest(t, s, "/api/alerts/resolve", map[string]string{"alertId": first})
	if resolved, _ := groupResolvedCount(t, s, dir); resolved != n {
		t.Fatalf("after re-resolve: %d", resolved)
	}
	groupResolutionRequest(t, s, "/api/alerts/unresolve", map[string]string{"groupId": "flood-high"})
	if resolved, _ := groupResolvedCount(t, s, dir); resolved != 0 {
		t.Fatalf("after group unresolve: %d", resolved)
	}
}

// A group resolution covers the alerts that existed when it was made; a live
// capture's later alerts in the same group stay open.
func TestGroupResolutionDoesNotCoverLaterAlerts(t *testing.T) {
	store := &ResolvedAlertsStore{Groups: map[string]ResolvedGroup{"r-low": {ResolvedAt: 1, Through: 100}}}
	earlier := &types.Alert{RuleName: "r", Severity: "low", DetectedAt: 100}
	later := &types.Alert{RuleName: "r", Severity: "low", DetectedAt: 101}
	if ok, _ := isAlertResolved(earlier, "a", store); !ok {
		t.Fatal("earlier alert not covered")
	}
	if ok, _ := isAlertResolved(later, "b", store); ok {
		t.Fatal("later alert covered")
	}
}

// Version 1 files listed every alert; unresolving the group must remove those
// entries too.
func TestUnresolveGroupRemovesLegacyEntries(t *testing.T) {
	dir := t.TempDir()
	rows := []proto.Message{&types.Alert{Timestamp: 1, RuleName: "r", Severity: "low"}, &types.Alert{Timestamp: 2, RuleName: "r", Severity: "low"}}
	writeTimelineAuditFile(t, dir, "Alert", types.Type_NC_Alert, rows)
	legacy := map[string]any{"alerts": map[string]any{}}
	for _, row := range rows {
		id := alertResponse(row.(*types.Alert)).AlertID
		legacy["alerts"].(map[string]any)[id] = map[string]any{"alertId": id, "resolvedAt": 7}
	}
	raw, _ := json.MarshalIndent(legacy, "", "  ")
	if err := os.WriteFile(filepath.Join(dir, "resolved_alerts.json"), raw, 0644); err != nil {
		t.Fatal(err)
	}
	s := &Server{outDir: dir}
	if resolved, _ := groupResolvedCount(t, s, dir); resolved != 2 {
		t.Fatalf("legacy file not read: %d", resolved)
	}
	groupResolutionRequest(t, s, "/api/alerts/unresolve", map[string]string{"groupId": "r-low"})
	if resolved, _ := groupResolvedCount(t, s, dir); resolved != 0 {
		t.Fatalf("legacy entries survived: %d", resolved)
	}
}
