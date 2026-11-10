package webui

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestTopCategoriesLimitsAndBreaksTiesByName(t *testing.T) {
	counts := map[string]int{"big": 100}
	for i := range 30 {
		counts[fmt.Sprintf("tie-%02d", i)] = 1
	}
	got := topCategories(counts, maxChartCategories)
	if len(got) != maxChartCategories {
		t.Fatalf("got %d categories, want %d", len(got), maxChartCategories)
	}
	if got[0].key != "big" || got[1].key != "tie-00" || got[19].key != "tie-18" {
		t.Fatalf("unexpected order: first=%s second=%s last=%s", got[0].key, got[1].key, got[19].key)
	}
	for range 10 {
		again := topCategories(counts, maxChartCategories)
		for i := range got {
			if again[i] != got[i] {
				t.Fatalf("selection is not deterministic at %d", i)
			}
		}
	}
}

func TestMissingAuditFileIsNoChartData(t *testing.T) {
	_, err := NewChartGenerator("DeviceProfile", "DeviceManufacturer", "pie", "", true, 1000).GenerateChartFromDirs([]string{t.TempDir()})
	if !errors.Is(err, errNoChartData) {
		t.Fatalf("err = %v, want errNoChartData", err)
	}
	if _, err := NewChartGenerator("DeviceProfile", "DeviceManufacturer", "pie", "", true, 1000).GenerateChartFromDirs(nil); errors.Is(err, errNoChartData) {
		t.Fatal("a missing scope must remain an error, not an empty chart")
	}
}

func TestChartHandlerAnswersNoDataWithNoContent(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/chart/data?type=File&field=MagikaLabel&chartType=pie", nil)
	HandleChartData(t.TempDir())(rec, req)
	if rec.Code != http.StatusNoContent || rec.Body.Len() != 0 {
		t.Fatalf("status=%d body=%q, want empty 204", rec.Code, rec.Body.String())
	}
}
