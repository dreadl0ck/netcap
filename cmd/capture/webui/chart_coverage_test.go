package webui

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dreadl0ck/netcap/types"
	"github.com/gogo/protobuf/proto"
)

func TestChartCoverageLabelsActualSampling(t *testing.T) {
	dir := t.TempDir()
	writeTimelineAuditFile(t, dir, "TCP", types.Type_NC_TCP, []proto.Message{
		&types.TCP{Timestamp: 1000000000, SrcPort: 10},
		&types.TCP{Timestamp: 2000000000, SrcPort: 20},
		&types.TCP{Timestamp: 3000000000, SrcPort: 30},
	})
	s := &Server{outDir: dir}
	for _, cap := range []int{2, 3} {
		result, err := s.aggregateChartDataAcrossDirs(t.Context(), []string{dir}, "TCP", "SrcPort", "1s", cap)
		if err != nil {
			t.Fatal(err)
		}
		if result.Coverage.Sampled != (cap == 2) || result.Coverage.SourceBuckets != 3 || result.Coverage.DisplayedBuckets != cap || len(result.Coverage.Limitations) == 0 {
			t.Fatalf("coverage: %+v", result)
		}
	}
}

func TestChartDataBucketMeansPreserveRecordStatistics(t *testing.T) {
	dir := t.TempDir()
	rows := make([]proto.Message, 0, 4097)
	for range 2048 {
		rows = append(rows, &types.TCP{Timestamp: 2, SrcPort: 10}, &types.TCP{Timestamp: 3, SrcPort: 30})
	}
	rows = append(rows, &types.TCP{Timestamp: 1_000_000_000, SrcPort: 40})
	writeTimelineAuditFile(t, dir, "TCP", types.Type_NC_TCP, rows)
	result, err := (&Server{}).aggregateChartDataAcrossDirs(t.Context(), []string{dir}, "TCP", "SrcPort", "1s", 2)
	if err != nil {
		t.Fatal(err)
	}
	if result.Count != 2 || len(result.Data) != 2 ||
		result.Data[0] != (ChartDataPoint{Timestamp: 0, Value: 20}) ||
		result.Data[1] != (ChartDataPoint{Timestamp: 1_000_000_000, Value: 40}) ||
		result.MinValue != 10 || result.MaxValue != 40 || result.AvgValue != (4096*20.+40)/4097 {
		t.Fatalf("unexpected chart data: %+v", result)
	}
}

func TestChartJSONPreservesNegativeExtrema(t *testing.T) {
	for _, values := range [][2]int32{{-1, 5}, {-9, -2}} {
		dir := t.TempDir()
		writeTimelineAuditFile(t, dir, "HTTP", types.Type_NC_HTTP, []proto.Message{
			&types.HTTP{Timestamp: 1, ResContentLength: values[0]},
			&types.HTTP{Timestamp: 2, ResContentLength: values[1]},
		})
		result, err := (&Server{}).aggregateChartDataAcrossDirs(t.Context(), []string{dir}, "HTTP", "ResContentLength", "1s", 2)
		if err != nil {
			t.Fatal(err)
		}
		if result.MinValue != float64(values[0]) || result.MaxValue != float64(values[1]) {
			t.Fatalf("values %v: min=%v max=%v", values, result.MinValue, result.MaxValue)
		}
	}
}

func TestChartJSONBucketLimitAndRetry(t *testing.T) {
	dir := t.TempDir()
	rows := make([]proto.Message, maxJSONChartBuckets+1)
	for i := range rows {
		rows[i] = &types.TCP{Timestamp: int64(i + 1), SrcPort: 10}
	}
	writeTimelineAuditFile(t, dir, "TCP", types.Type_NC_TCP, rows)
	s := &Server{outDir: dir}
	request := "/api/charts/data?format=json&type=TCP&field=SrcPort&interval="
	w := httptest.NewRecorder()
	s.handleChartData(w, httptest.NewRequest(http.MethodGet, request+"1ns", nil))
	if w.Code != http.StatusUnprocessableEntity || !strings.Contains(w.Body.String(), "use a larger interval") {
		t.Fatalf("oversized chart: %d %s", w.Code, w.Body.String())
	}
	w = httptest.NewRecorder()
	s.handleChartData(w, httptest.NewRequest(http.MethodGet, request+"1s", nil))
	var result ChartDataResponse
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &result) != nil || len(result.Data) != 1 || result.Data[0].Value != 10 {
		t.Fatalf("coarser chart: %d %s", w.Code, w.Body.String())
	}
	left, right := t.TempDir(), t.TempDir()
	writeTimelineAuditFile(t, left, "TCP", types.Type_NC_TCP, rows[:maxJSONChartBuckets])
	writeTimelineAuditFile(t, right, "TCP", types.Type_NC_TCP, rows[maxJSONChartBuckets:])
	if _, err := s.aggregateChartDataAcrossDirs(t.Context(), []string{left, right}, "TCP", "SrcPort", "1ns", 2); !errors.Is(err, errChartBucketLimit) {
		t.Fatalf("merged chart exceeded bucket limit: %v", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := s.extractChartData(ctx, filepath.Join(dir, "TCP.ncap.gz"), "TCP", "SrcPort", "1ns"); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled chart: %v", err)
	}
}

func TestChartJSONReadsPlainAuditAndRejectsBadPreferredSource(t *testing.T) {
	dir := t.TempDir()
	rows := []proto.Message{&types.TCP{Timestamp: 1, SrcPort: 53}}
	writeTimelineAuditFilePlain(t, dir, "TCP", types.Type_NC_TCP, rows)
	s := &Server{outDir: dir}
	query := func(auditType string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		s.handleChartData(w, httptest.NewRequest(http.MethodGet, "/api/charts/data?format=json&type="+auditType+"&field=SrcPort", nil))
		return w
	}
	w := query("TCP")
	var result ChartDataResponse
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &result) != nil || len(result.Data) != 1 || result.Data[0].Value != 53 {
		t.Fatalf("plain audit chart: %d %s", w.Code, w.Body.String())
	}
	if w := query("UnregisteredType"); w.Code != http.StatusBadRequest {
		t.Fatalf("invalid audit type: %d %s", w.Code, w.Body.String())
	}
	compressed := writeTimelineAuditFile(t, dir, "TCP", types.Type_NC_UDP, []proto.Message{&types.UDP{Timestamp: 1, SrcPort: 99}})
	if w := query("TCP"); w.Code != http.StatusInternalServerError || !strings.Contains(w.Body.String(), "unexpected audit header type") {
		t.Fatalf("mismatched header: %d %s", w.Code, w.Body.String())
	}
	if err := os.WriteFile(compressed, []byte("not compressed"), 0600); err != nil {
		t.Fatal(err)
	}
	if w := query("TCP"); w.Code != http.StatusInternalServerError {
		t.Fatalf("corrupt compressed audit: %d %s", w.Code, w.Body.String())
	}
	if err := os.Remove(compressed); err != nil {
		t.Fatal(err)
	}
	linked := writeTimelineAuditFile(t, t.TempDir(), "TCP", types.Type_NC_TCP, rows)
	if err := os.Symlink(linked, compressed); err != nil {
		t.Fatal(err)
	}
	if w := query("TCP"); w.Code != http.StatusInternalServerError || !strings.Contains(w.Body.String(), "invalid artifact path") {
		t.Fatalf("linked compressed audit: %d %s", w.Code, w.Body.String())
	}
}

func TestChartFieldDiscoveryQualifiesPrefix(t *testing.T) {
	dir := t.TempDir()
	rows := make([]proto.Message, 101)
	for i := range rows {
		rows[i] = &types.TCP{Timestamp: int64(i + 1)}
	}
	rows[100] = &types.TCP{Timestamp: 101, SrcPort: 1234}
	writeTimelineAuditFile(t, dir, "TCP", types.Type_NC_TCP, rows)
	s := &Server{outDir: dir}
	w := httptest.NewRecorder()
	s.handleChartFields(w, httptest.NewRequest("GET", "/api/charts/fields?type=TCP", nil))
	if w.Code != 200 {
		t.Fatalf("%d: %s", w.Code, w.Body.String())
	}
	var result ChartFieldsResponse
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.SampleLimit != 100 || !strings.Contains(result.Discovery, "prefix") {
		t.Fatalf("unqualified sample: %+v", result)
	}
	for _, field := range result.Fields {
		if field.Name == "SrcPort" {
			t.Fatal("sample unexpectedly included record 101")
		}
	}
	hierarchy, err := buildProtocolHierarchy(dir)
	if err != nil {
		t.Fatal(err)
	}
	if hierarchy.Basis != "schematic" || len(hierarchy.Limitations) != 2 {
		t.Fatalf("unqualified relationships: %+v", hierarchy)
	}
}

func TestRenderedChartCoverageReportsPrefixAndRejectsZeroInterval(t *testing.T) {
	dir := t.TempDir()
	writeTimelineAuditFile(t, dir, "TCP", types.Type_NC_TCP, []proto.Message{&types.TCP{Timestamp: 1, SrcPort: 1}, &types.TCP{Timestamp: 2, SrcPort: 2}, &types.TCP{Timestamp: 3, SrcPort: 3}})
	for _, interval := range []string{"", "1ns"} {
		generator := NewChartGenerator("TCP", "SrcPort", "line", interval, true, 2)
		if _, err := generator.GenerateChart(dir); err != nil {
			t.Fatal(err)
		}
		coverage := generator.Coverage
		if !coverage.ValuesKnown || !coverage.LimitReached || coverage.RenderedValues != 2 || coverage.SourcesRead != 1 || coverage.SourcesRequested != 1 {
			t.Fatalf("incorrect HTML coverage %+v", coverage)
		}
	}
	generator := NewChartGenerator("TCP", "SrcPort", "line", "0s", true, 2)
	if _, err := generator.GenerateChart(dir); err == nil {
		t.Fatal("zero interval accepted")
	}
	s := &Server{}
	if _, err := s.extractChartData(t.Context(), filepath.Join(dir, "TCP.ncap.gz"), "TCP", "SrcPort", "0s"); err == nil {
		t.Fatal("zero JSON interval accepted")
	}
}
