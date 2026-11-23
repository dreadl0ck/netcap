package webui

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gogo/protobuf/proto"

	"github.com/dreadl0ck/netcap/internal/rules"
	"github.com/dreadl0ck/netcap/types"
)

// The VRRP decoder writes NC_VRRPv2 records to VRRP.ncap.gz. Treating the file
// name as the record type failed the timeline and therefore the analysis.
func TestAnalysisCompletesWithVRRPAudit(t *testing.T) {
	s, input, dir := reanalysisFixture(t)
	delete(s.completedFiles, input)
	s.fileBPFFilters = map[string]string{}
	s.rulesConfig = &rules.Config{Rules: []*rules.Rule{{Name: "vrrp", Type: "VRRPv2", Expression: "VirtualRtrID == 7", Enabled: true}}}
	if err := os.Remove(filepath.Join(dir, "HTTP.ncap.gz")); err != nil {
		t.Fatal(err)
	}
	writeTimelineAuditFile(t, dir, "VRRP", types.Type_NC_VRRPv2, []proto.Message{
		&types.VRRPv2{Timestamp: 1_000, VirtualRtrID: 7, SrcIP: "192.0.2.1", DstIP: "224.0.0.18"},
	})
	if err := s.completeAnalysis(&AnalysisJob{InputFile: input, OutputDir: dir}, 5*time.Second); err != nil {
		t.Fatalf("VRRP audit failed analysis: %v", err)
	}
	status := timelineIndexFor(dir)
	if status.State != timelineStateReady || status.Index == nil {
		t.Fatalf("timeline not ready: %s %s", status.State, status.Err)
	}
	found := false
	for _, track := range status.Index.Types {
		found = found || track.Name == "VRRPv2"
	}
	if !found {
		t.Fatal("timeline has no VRRPv2 track")
	}
	assertSingleReplayAlert(t, dir, "vrrp", 1_000)
}

// v0.16.11 wrote GTP control records to GTPv1U.ncap.gz; existing output stays readable.
func TestLegacyGTPv1UAuditIsReadable(t *testing.T) {
	dir := t.TempDir()
	writeTimelineAuditFile(t, dir, "GTPv1U", types.Type_NC_GTP, []proto.Message{&types.GTP{Timestamp: 5}})

	files, err := ListAuditFiles(dir)
	if err != nil || len(files) != 1 || files[0].Type != "GTP" || files[0].RecordCount != 1 {
		t.Fatalf("listing: %+v %v", files, err)
	}
	for _, requested := range []string{"GTP", "GTPv1U"} {
		w := httptest.NewRecorder()
		HandleAuditRecords(dir)(w, httptest.NewRequest(http.MethodGet, "/api/audit/"+requested+"/meta", nil))
		var meta map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &meta); err != nil || w.Code != http.StatusOK || meta["recordCount"] != float64(1) || meta["recordCountComplete"] != true {
			t.Fatalf("%s meta: %d %s", requested, w.Code, w.Body)
		}
	}
	if index := waitForTimelineIndex(t, dir); index.TotalEvents != 1 || len(index.Types) != 1 || index.Types[0].Name != "GTP" {
		t.Fatalf("timeline: %d events", index.TotalEvents)
	}
}

// With both names present, readers use the canonical file and list the type once.
func TestCanonicalAuditFileWinsOverAlias(t *testing.T) {
	dir := t.TempDir()
	writeTimelineAuditFile(t, dir, "GTPv1U", types.Type_NC_GTP, []proto.Message{&types.GTP{Timestamp: 1}})
	canonical := writeTimelineAuditFile(t, dir, "GTP", types.Type_NC_GTP, []proto.Message{&types.GTP{Timestamp: 1}, &types.GTP{Timestamp: 2}})
	if got := auditFilePath(dir, "GTPv1U"); got != canonical {
		t.Fatalf("resolved %s, want %s", got, canonical)
	}
	files, err := ListAuditFiles(dir)
	if err != nil || len(files) != 1 || files[0].Name != "GTP.ncap.gz" || files[0].RecordCount != 2 {
		t.Fatalf("listing: %+v %v", files, err)
	}
}
