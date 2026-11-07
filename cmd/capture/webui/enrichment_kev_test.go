package webui

import (
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/dreadl0ck/netcap/internal/decoder/db"
	"github.com/dreadl0ck/netcap/internal/resolvers"
	"github.com/dreadl0ck/netcap/internal/vulndb"
	"github.com/dreadl0ck/netcap/types"
	"github.com/gogo/protobuf/proto"
)

func TestRealProductionKEVHTTP(t *testing.T) {
	root := os.Getenv("NETCAP_TEST_ENRICHMENT_PRODUCTION_ROOT")
	if root == "" {
		t.Skip("explicit production clean install required")
	}
	t.Setenv("NC_ENRICHMENT_ROOT", root)
	dir := t.TempDir()
	writeTimelineAuditFile(t, dir, "Vulnerability", types.Type_NC_Vulnerability, []proto.Message{&types.Vulnerability{ID: "CVE-2024-27834"}, &types.Vulnerability{ID: "CVE-2099-999999999"}})
	path := filepath.Join(t.TempDir(), vulndb.FileName)
	builder, e := vulndb.Create(path)
	if e != nil {
		t.Fatal(e)
	}
	if e = builder.AddVulnerability(vulndb.Vulnerability{ID: "CVE-2024-27834", References: []vulndb.Reference{{URL: "https://example.org/advisory", Source: "nvd"}}}); e != nil {
		t.Fatal(e)
	}
	if e = builder.Finish(); e != nil {
		t.Fatal(e)
	}
	oldDB, oldPath := db.VulnerabilitiesIndex, resolvers.DataBaseFolderPath
	defer func() { db.VulnerabilitiesIndex = oldDB; resolvers.DataBaseFolderPath = oldPath }()
	db.VulnerabilitiesIndex = nil
	resolvers.DataBaseFolderPath = filepath.Dir(path)
	server := newTimelineTestServer(dir)
	w := httptest.NewRecorder()
	server.handleVulnerabilities(w, httptest.NewRequest("GET", "/api/vulnerabilities", nil))
	var result VulnerabilitiesResponse
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &result) != nil || result.KEVStatus != "available" || result.TotalVulns != 2 || result.TotalExploits != 0 || len(result.Vulnerabilities) != 2 {
		t.Fatalf("HTTP response mismatch: %d %s", w.Code, w.Body.String())
	}
	for _, v := range result.Vulnerabilities {
		if v.ID == "CVE-2024-27834" {
			if v.KEV == nil || v.KEV.DateAdded != "2026-11-04" || v.KEV.Ransomware != "Unknown" || len(v.References) != 1 || v.References[0].URL != "https://example.org/advisory" {
				t.Fatalf("KEV/reference join mismatch: %+v", v)
			}
		} else if v.KEV != nil {
			t.Fatal("KEV sidecar invented an applicability match")
		}
	}
}

func TestRealProductionKEVSidecar(t *testing.T) {
	root := os.Getenv("NETCAP_TEST_ENRICHMENT_PRODUCTION_ROOT")
	if root == "" {
		t.Skip("explicit real production clean install required")
	}
	t.Setenv("NC_ENRICHMENT_ROOT", root)
	result := &VulnerabilitiesResponse{TotalVulns: 2, TotalExploits: 0, Vulnerabilities: []VulnerabilitySummary{{ID: "CVE-2024-27834", Count: 1, References: []vulndb.Reference{{URL: "https://example.org/reference", Source: "nvd"}}}, {ID: "CVE-2099-999999999", Count: 1}}}
	attachKEV(result)
	if result.KEVStatus != "available" || result.TotalVulns != 2 || result.TotalExploits != 0 || len(result.Vulnerabilities) != 2 || result.Vulnerabilities[0].KEV == nil || result.Vulnerabilities[0].KEV.DateAdded != "2026-11-04" || result.Vulnerabilities[0].KEV.Ransomware != "Unknown" || result.Vulnerabilities[1].KEV != nil || result.Vulnerabilities[0].References[0].URL != "https://example.org/reference" {
		t.Fatalf("production KEV sidecar mismatch: %+v", result)
	}
}

func TestMissingOptionalKEVPreservesVulnerabilityResponse(t *testing.T) {
	t.Setenv("NC_ENRICHMENT_ROOT", t.TempDir())
	response := &VulnerabilitiesResponse{TotalVulns: 7, TotalExploits: 3, Vulnerabilities: []VulnerabilitySummary{{ID: "CVE-2024-1234", Count: 7, References: []vulndb.Reference{{URL: "https://example.org/reference", Source: "nvd"}}}}}
	attachKEV(response)
	if response.KEVStatus != "unavailable" || response.TotalVulns != 7 || response.TotalExploits != 3 || len(response.Vulnerabilities) != 1 || response.Vulnerabilities[0].Count != 7 || response.Vulnerabilities[0].References[0].URL != "https://example.org/reference" || response.Vulnerabilities[0].KEV != nil {
		t.Fatalf("optional absence changed matches/references: %+v", response)
	}
}
