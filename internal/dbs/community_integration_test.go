package dbs

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/dreadl0ck/netcap/internal/vulndb"
)

func TestInstalledCommunityCompatibility(t *testing.T) {
	dir := os.Getenv("NETCAP_TEST_COMMUNITY_DBS")
	if dir == "" {
		t.Skip("set NETCAP_TEST_COMMUNITY_DBS to a downloaded community dbs directory")
	}
	metadata, err := ManagedReleaseMetadata(dir)
	if err != nil || metadata.Layout != V3Layout || metadata.VulnDBSchema != vulndb.SchemaVersion {
		t.Fatalf("installed release: %+v %v", metadata, err)
	}
	db, err := vulndb.Open(filepath.Join(dir, vulndb.FileName))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, tc := range []struct {
		version string
		want    bool
	}{{"2.4.49", true}, {"2.4.51", false}} {
		vulns, err := db.Vulnerabilities("apache", "http_server", tc.version)
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, v := range vulns {
			if v.ID == "CVE-2021-41773" {
				found = true
				if len(v.References) == 0 || v.MatchStatus != "cpe-product-version" {
					t.Fatalf("missing references or structured applicability: %+v", v)
				}
			}
		}
		if found != tc.want {
			t.Fatalf("Apache %s CVE-2021-41773 match=%v, want %v", tc.version, found, tc.want)
		}
	}
}
