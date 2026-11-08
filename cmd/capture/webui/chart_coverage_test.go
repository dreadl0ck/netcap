package webui

import (
	"encoding/json"
	"net/http/httptest"
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
		result, err := s.aggregateChartDataAcrossDirs([]string{dir}, "TCP", "SrcPort", "1s", cap)
		if err != nil {
			t.Fatal(err)
		}
		if result.Coverage.Sampled != (cap == 2) || result.Coverage.SourceBuckets != 3 || result.Coverage.DisplayedBuckets != cap || len(result.Coverage.Limitations) == 0 {
			t.Fatalf("coverage: %+v", result)
		}
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
