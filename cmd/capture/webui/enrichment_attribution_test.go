package webui

import (
	"github.com/dreadl0ck/netcap/internal/enrichment"
	"github.com/dreadl0ck/netcap/internal/webtech/testfixture"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCatalogueAttributionFullNoticesAndVerifiedSources(t *testing.T) {
	f, err := testfixture.Build()
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(t.TempDir(), "enrichment")
	if err = f.Install(root); err != nil {
		t.Fatal(err)
	}
	result := readCatalogueAttribution(root, f.Trust, time.Unix(f.Now, 0))
	if result.State != "verified-installed" || !strings.Contains(result.InstalledNotices, "Copyright (c) 2025 ProjectDiscovery, Inc.") || !strings.Contains(result.InstalledNotices, "THE SOFTWARE IS PROVIDED") || !strings.Contains(result.InstalledNotices, "daffainfo") || !strings.Contains(result.InstalledNotices, "ricardomaia") {
		t.Fatal("missing full attribution")
	}
	dir, err := enrichment.Resolve(root, f.Trust, time.Unix(f.Now, 0))
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(dir, enrichment.NoticesName), []byte("tampered"), 0600); err != nil {
		t.Fatal(err)
	}
	result = readCatalogueAttribution(root, f.Trust, time.Unix(f.Now, 0))
	if result.State != "invalid-or-stale" || result.InstalledNotices != "" || len(result.InstalledSources) != 0 {
		t.Fatal("unverified notice returned")
	}
	r := httptest.NewRecorder()
	(&Server{}).handleEnrichmentAttribution(r, httptest.NewRequest(http.MethodGet, "/api/enrichment/attribution", nil))
	if r.Code != http.StatusOK || !strings.Contains(r.Body.String(), "first_party_grant") || !strings.Contains(r.Body.String(), "NUCLEI-LICENSE.txt") || r.Header().Get("Cache-Control") != "no-store" {
		t.Fatal(r.Code, r.Body.String())
	}
	r = httptest.NewRecorder()
	(&Server{}).handleEnrichmentAttribution(r, httptest.NewRequest(http.MethodPost, "/api/enrichment/attribution", nil))
	if r.Code != 405 {
		t.Fatal(r.Code)
	}
}
