package resolvers_test

import (
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/internal/dbs"
	"github.com/dreadl0ck/netcap/internal/resolvers"
	"github.com/dreadl0ck/netcap/internal/vulndb"
)

// Exercise the real transactional updater using only synthetic, locally reviewed
// fixture bytes. This registry grants no rights to any production dataset.
func TestPopularityFileSurvivesCoreUpdater(t *testing.T) {
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	sum := func(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }
	writeJSON := func(path string, v any) []byte {
		b, err := json.Marshal(v)
		must(err)
		must(os.WriteFile(path, b, 0600))
		return b
	}
	build, candidate, archives := t.TempDir(), t.TempDir(), t.TempDir()
	year := time.Now().Year()
	f, err := os.Create(filepath.Join(build, fmt.Sprintf("nvdcve-2.0-%d.json.gz", year)))
	must(err)
	gz := gzip.NewWriter(f)
	_, err = gz.Write([]byte(`{"format":"NVD_CVE","version":"2.0","vulnerabilities":[{"cve":{"id":"CVE-2026-0001","descriptions":[{"lang":"en","value":"Synthetic fixture 1.0 test"}]}}]}`))
	must(err)
	must(gz.Close())
	must(f.Close())
	must(dbs.BuildVulnDB(build, candidate, year, false))
	db, err := vulndb.Open(filepath.Join(candidate, "netcap.sqlite"))
	must(err)
	meta, err := db.Meta()
	must(err)
	must(db.Close())
	var inputs []dbs.NVDInput
	must(json.Unmarshal([]byte(meta["nvd_inputs"]), &inputs))
	grant := "Permission to use and redistribute these synthetic test bytes only. No production dataset rights are granted."
	evidence := dbs.SourceEvidence{ID: "nvd", Origin: "urn:netcap:synthetic-popularity-update", Revision: "fixture-1", SHA256: meta["input_sha256"], Transformation: "synthetic test SQLite", GrantText: grant, GrantSHA256: sum([]byte(grant)), NoticeText: "Copyright: synthetic fixture only", GrantOrigin: "urn:netcap:synthetic-test-grant", GrantRevision: "1", NVDInputs: inputs}
	must(dbs.WriteCandidate(candidate, []dbs.SourceEvidence{evidence}))
	bytes, err := os.ReadFile(filepath.Join(candidate, dbs.CandidateFile))
	must(err)
	var c dbs.Candidate
	must(json.Unmarshal(bytes, &c))
	registry := filepath.Join(t.TempDir(), "reviews.json")
	registryBytes := writeJSON(registry, []dbs.ReviewedSource{{Evidence: evidence, Outputs: c.Files, Decision: "approved-for-publication", Reviewer: "synthetic-test", ReviewID: "fixture-only-1", ReviewedAt: "2026-10-01T00:00:00Z"}})
	pin := sum(registryBytes)
	release, err := dbs.PackV3WithRegistry(candidate, archives, registry, pin)
	must(err)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/dbs/v3/latest" {
			must(json.NewEncoder(w).Encode(release))
			return
		}
		if r.URL.Path == "/dbs/v3/"+release.Tarball {
			http.ServeFile(w, r, filepath.Join(archives, release.Tarball))
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()
	oldRoot, oldDBs, oldConfig := resolvers.ConfigRootPath, resolvers.DataBaseFolderPath, resolvers.CurrentConfig
	t.Cleanup(func() {
		resolvers.ConfigRootPath, resolvers.DataBaseFolderPath, resolvers.CurrentConfig = oldRoot, oldDBs, oldConfig
		resolvers.InitDNSWhitelist()
	})
	resolvers.ConfigRootPath = t.TempDir()
	resolvers.DataBaseFolderPath = filepath.Join(resolvers.ConfigRootPath, "dbs")
	must(os.Mkdir(resolvers.DataBaseFolderPath, 0700))
	must(os.WriteFile(filepath.Join(resolvers.DataBaseFolderPath, "domain-whitelist.csv"), []byte("1,legacy.com\n"), 0600))
	userDir := filepath.Join(resolvers.ConfigRootPath, "user-data")
	must(os.Mkdir(userDir, 0700))
	userFile := filepath.Join(userDir, "popularity.csv")
	before := []byte("1,example.com\n")
	must(os.WriteFile(userFile, before, 0600))
	info, err := os.Stat(userFile)
	must(err)
	for _, force := range []bool{true, false, true} {
		must(dbs.DownloadDBsWithRegistry(server.URL, force, nil, registry, pin))
		after, err := os.ReadFile(userFile)
		must(err)
		afterInfo, err := os.Stat(userFile)
		must(err)
		if string(before) != string(after) || !os.SameFile(info, afterInfo) {
			t.Fatal("core updater touched operator popularity file")
		}
		l, _, err := resolvers.LoadDomainPopularityList(userFile, "rank-domain", resolvers.DataBaseFolderPath)
		must(err)
		if !l.ContainsDNS("www.example.com") {
			t.Fatal("lost membership after update")
		}
	}
	resolvers.CurrentConfig = resolvers.Config{}
	resolvers.InitDNSWhitelist()
	if resolvers.IsWhitelistedDomain("legacy.com") {
		t.Fatal("legacy data active")
	}
}
