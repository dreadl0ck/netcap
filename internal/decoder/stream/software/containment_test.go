package software

import (
	"github.com/ua-parser/uap-go/uaparser"
	"os"
	"path/filepath"
	"testing"

	decoderconfig "github.com/dreadl0ck/netcap/internal/decoder/config"
	"github.com/dreadl0ck/netcap/internal/decoder/db"
	"github.com/dreadl0ck/netcap/internal/resolvers"
	"github.com/dreadl0ck/netcap/internal/vulndb"
)

func TestSoftwareNVDIndependentOfLegacyCMS(t *testing.T) {
	oldPath, oldConfig, oldIndex := resolvers.DataBaseFolderPath, decoderconfig.Instance, db.VulnerabilitiesIndex
	oldCMS, oldHeaders, oldCookies := cmsDB, CMSHeaders, CMSCookies
	oldHash, oldHassh := HashDBMap, hasshDB
	oldLog := softwareLog
	oldParser, oldParserError := parser, errInitUAParser
	var err error
	parser, err = uaparser.NewFromBytes([]byte("user_agent_parsers: []\nos_parsers: []\ndevice_parsers: []\n"))
	if err != nil {
		t.Fatal(err)
	}
	errInitUAParser = nil
	dir := t.TempDir()
	resolvers.DataBaseFolderPath = dir
	cfg := *decoderconfig.DefaultConfig
	cfg.Out = t.TempDir()
	decoderconfig.Instance = &cfg
	t.Cleanup(func() {
		db.Close(db.VulnerabilitiesIndex)
		db.VulnerabilitiesIndex = oldIndex
		resolvers.DataBaseFolderPath = oldPath
		decoderconfig.Instance = oldConfig
		cmsDB, CMSHeaders, CMSCookies = oldCMS, oldHeaders, oldCookies
		HashDBMap, hasshDB = oldHash, oldHassh
		softwareLog = oldLog
		parser, errInitUAParser = oldParser, oldParserError
	})
	b, err := vulndb.Create(db.Path(dir))
	if err != nil {
		t.Fatal(err)
	}
	if err = b.AddVulnerability(vulndb.Vulnerability{ID: "fixture-only", Description: "fixture-vendor fixture-product", Versions: []string{"1"}}); err != nil {
		b.Abort()
		t.Fatal(err)
	}
	if err = b.Finish(); err != nil {
		t.Fatal(err)
	}
	// Deliberately invalid old CMS contents must not gate NVD initialization.
	legacy := []byte("not a cleared CMS catalogue")
	path := filepath.Join(dir, "cmsdb.json")
	if err = os.WriteFile(path, legacy, 0600); err != nil {
		t.Fatal(err)
	}
	cmsDB = map[string]*cmsInfo{"stale": {}}
	CMSHeaders = map[string]struct{}{"X-Stale": {}}
	if err = Decoder.PostInit(Decoder); err != nil {
		t.Fatal(err)
	}
	if db.VulnerabilitiesIndex == nil {
		t.Fatal("NVD was gated by missing SSH/CMS inputs")
	}
	vulns, err := db.VulnerabilitiesIndex.Vulnerabilities("fixture-vendor", "fixture-product", "1")
	if err != nil || len(vulns) != 1 || vulns[0].ID != "fixture-only" {
		t.Fatalf("NVD lookup lost: %+v %v", vulns, err)
	}
	if len(cmsDB) != 0 || len(CMSHeaders) != 0 || len(CMSCookies) != 0 {
		t.Fatal("stale CMS state survived")
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != string(legacy) {
		t.Fatal("legacy data modified")
	}
}
