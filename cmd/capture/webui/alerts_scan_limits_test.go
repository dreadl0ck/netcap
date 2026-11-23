package webui

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gogo/protobuf/proto"

	"github.com/dreadl0ck/netcap/types"
)

// MCP-23: paged views used to stop at 256 MiB of decoded alerts even though
// they stream. Compressible alerts reach that with a small stored file.
func TestAlertViewsAboveDecodedScanCap(t *testing.T) {
	if testing.Short() {
		t.Skip("decodes 260 MiB")
	}
	dir := t.TempDir()
	const count = 520
	description := strings.Repeat("x", 512<<10)
	rows := make([]proto.Message, count)
	for i := range rows {
		rows[i] = &types.Alert{RuleName: "fixture", Severity: "info", Timestamp: int64(i+1) * int64(time.Millisecond), Description: description}
	}
	path := writeTimelineAuditFile(t, dir, "Alert", types.Type_NC_Alert, rows)
	if info, err := os.Stat(path); err != nil || info.Size() > 16<<20 {
		t.Fatalf("fixture must be small on disk: %v %v", info, err)
	}
	s := &Server{outDir: dir}

	stats := httptest.NewRecorder()
	s.handleAlertStats(stats, httptest.NewRequest(http.MethodGet, "/api/alerts/stats", nil))
	var summary struct{ TotalAlerts int }
	if err := json.Unmarshal(stats.Body.Bytes(), &summary); err != nil || stats.Code != http.StatusOK || summary.TotalAlerts != count {
		t.Fatalf("stats: %d %.200s", stats.Code, stats.Body)
	}
	grouped := httptest.NewRecorder()
	s.handleGroupedAlerts(grouped, httptest.NewRequest(http.MethodGet, "/api/alerts/grouped?mcpPage=true&pageLimit=1&pageFields=count", nil))
	if grouped.Code != http.StatusOK || !strings.Contains(grouped.Body.String(), fmt.Sprintf(`"totalCount":%d`, count)) {
		t.Fatalf("grouped: %d %.200s", grouped.Code, grouped.Body)
	}
	for _, offset := range []int{0, count - 1} {
		raw := httptest.NewRecorder()
		s.handleAlerts(raw, httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/alerts?mcpPage=true&pageLimit=1&pageOffset=%d&pageFields=timestamp", offset), nil))
		if raw.Code != http.StatusOK || !strings.Contains(raw.Body.String(), fmt.Sprintf(`"totalCount":%d`, count)) {
			t.Fatalf("raw offset %d: %d %.200s", offset, raw.Code, raw.Body)
		}
	}
}

// Each limit names itself; the old message printed every limit at once,
// including "0 decoded bytes" for views without a decoded total.
func TestAlertScanLimitMessages(t *testing.T) {
	dir := t.TempDir()
	row := &types.Alert{RuleName: "fixture", Description: strings.Repeat("x", 512)}
	path := writeTimelineAuditFile(t, dir, "Alert", types.Type_NC_Alert, []proto.Message{row, row, row})
	frame := proto.Size(row)
	s := &Server{outDir: dir}
	for _, tc := range []struct {
		name                  string
		bytes, rows, frameCap int
		want                  string
	}{
		{"exact rows", 0, 3, frame, ""},
		{"rows", 0, 2, frame, "alert audit exceeds 2 records"},
		{"frame", 0, 3, frame - 1, fmt.Sprintf("an alert record exceeds %d bytes", frame-1)},
		{"decoded total", 2*frame + 1, 3, frame, fmt.Sprintf("decoded alert audit exceeds %d bytes", 2*frame+1)},
	} {
		_, err := s.scanAlertAudit(t.Context(), path, tc.bytes, tc.rows, tc.frameCap, func(AlertResponse) error { return nil })
		if tc.want == "" {
			if err != nil {
				t.Fatalf("%s: %v", tc.name, err)
			}
			continue
		}
		if !errors.Is(err, errAlertPageSourceLimit) || !strings.HasSuffix(err.Error(), tc.want) {
			t.Fatalf("%s: %v, want suffix %q", tc.name, err, tc.want)
		}
	}
}

// Typical alerts serialize to 1-2.3 KB. With 4 KiB SQLite pages each such row
// took a whole overflow page; 64 KiB pages keep them local.
func TestRawAlertSpillCapacity(t *testing.T) {
	rows := make([]proto.Message, 2000)
	for i := range rows {
		rows[i] = &types.Alert{RuleName: "fixture", Timestamp: int64(i+1) * int64(time.Millisecond), Description: fmt.Sprintf("%05d", i) + strings.Repeat("d", 1400)}
	}
	path := writeTimelineAuditFile(t, t.TempDir(), "Alert", types.Type_NC_Alert, rows)
	s := &Server{}
	w := httptest.NewRecorder()
	s.serveRawAlertPageWithBudget(w, httptest.NewRequest(http.MethodGet, "/api/alerts?mcpPage=true&pageLimit=1&pageFields=timestamp", nil), path, 0, 6<<20)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"totalCount":2000`) {
		t.Fatalf("2000 rows of ~1.5 KB did not fit 6 MiB of scratch: %d %.200s", w.Code, w.Body)
	}
}
