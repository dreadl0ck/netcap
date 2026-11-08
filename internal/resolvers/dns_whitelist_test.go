package resolvers

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func popularityFile(t *testing.T, data string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "list.csv")
	if err := os.WriteFile(p, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	return p
}
func TestPopularityFormatsAndBoundaries(t *testing.T) {
	for _, tc := range []struct{ format, data string }{
		{"rank-domain", "1,EXAMPLE.CO.UK.\r\n2,bücher.de\r\n3,alice.github.io\r\n4,www.ck\r\n5,example.co.uk\r\n"},
		{"netapi", "NetAPI_Rank,Domain\r\n1,example.co.uk\r\n2,xn--bcher-kva.de\r\n3,alice.github.io\r\n4,www.ck\r\n5,EXAMPLE.CO.UK\r\n"},
		{"majestic", "GlobalRank,TldRank,Domain,TLD,RefSubNets,RefIPs,IDN_Domain,IDN_TLD,PrevGlobalRank,PrevTldRank,PrevRefSubNets,PrevRefIPs\n1,99,example.co.uk,uk,0,0,,,0,0,0,0\n2,99,bücher.de,de,0,0,,,0,0,0,0\n3,99,alice.github.io,io,0,0,,,0,0,0,0\n4,99,www.ck,ck,0,0,,,0,0,0,0\n5,99,example.co.uk,uk,0,0,,,0,0,0,0\n"},
	} {
		t.Run(tc.format, func(t *testing.T) {
			l, s, err := LoadDomainPopularityList(popularityFile(t, tc.data), tc.format, t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			if s.Rows != 5 || s.Loaded != 4 || s.Duplicates != 1 {
				t.Fatal(s)
			}
			for _, name := range []string{"www.EXAMPLE.co.uk.", "www.example.co.uk。", "bücher.de", "xn--bcher-kva.de", "x.alice.github.io", "x.www.ck"} {
				if !l.ContainsDNS(name) {
					t.Errorf("missing %q", name)
				}
			}
			for _, name := range []string{"co.uk", "other.co.uk", "bob.github.io", "github.io", "foo.ck", "www.ck.evil.com", "example.co.uk:443", "127.0.0.1", "::1", "https://example.co.uk", "*.example.co.uk", "a..example.co.uk", "\u200d.de"} {
				if l.ContainsDNS(name) {
					t.Errorf("overbroad %q", name)
				}
			}
			if !l.ContainsHTTP("www.example.co.uk:443") {
				t.Fatal("HTTP port")
			}
			for _, h := range []string{"example.co.uk:no", "example.co.uk:+443", "example.co.uk:0", "example.co.uk:65536", "[::1]:443"} {
				if l.ContainsHTTP(h) {
					t.Fatal(h)
				}
			}
		})
	}
}
func TestPopularityRejectsInput(t *testing.T) {
	for _, data := range []string{"", "<html>error</html>", "Rank,Domain\n1,example.com\n", "0,example.com\n", "1,com\n", "1,github.io\n", "1,foo.ck\n", "1,x.example.com\n", "1,127.0.0.1\n", "1,example.com\n1,other.com\n", "1,example.com,extra\n", "1,\"example.com\n", "1,example.invalid\n", "1,example.com\n2,a..com\n"} {
		l, _, err := LoadDomainPopularityList(popularityFile(t, data), "rank-domain", t.TempDir())
		if err == nil || l != nil {
			t.Fatalf("accepted %q", data)
		}
	}
	for _, format := range []string{"netapi", "majestic", "auto"} {
		if _, _, err := LoadDomainPopularityList(popularityFile(t, "rank,domain\n1,example.com\n"), format, t.TempDir()); err == nil {
			t.Fatal(format)
		}
	}
	// Unicode/ASCII collisions count as duplicate domains, never extra entries.
	_, s, err := LoadDomainPopularityList(popularityFile(t, "1,bücher.de\n2,xn--bcher-kva.de\n"), "rank-domain", t.TempDir())
	if err != nil || s.Duplicates != 1 {
		t.Fatal(s, err)
	}
}
func TestPopularityLimitsAndManagedPaths(t *testing.T) {
	root := t.TempDir()
	p := filepath.Join(root, "domain-whitelist.csv")
	if err := os.WriteFile(p, []byte("1,example.com\n"), 0600); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(t.TempDir(), "alias.csv")
	if err := os.Symlink(p, alias); err != nil {
		t.Fatal(err)
	}
	rootAlias := filepath.Join(t.TempDir(), "dbs")
	if err := os.Symlink(root, rootAlias); err != nil {
		t.Fatal(err)
	}
	for _, pair := range [][2]string{{p, root}, {alias, root}, {p, rootAlias}} {
		if _, _, err := LoadDomainPopularityList(pair[0], "rank-domain", pair[1]); err == nil {
			t.Fatal(pair)
		}
	}
	huge := popularityFile(t, "")
	f, err := os.OpenFile(huge, os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	err = f.Truncate(MaxPopularityBytes + 1)
	f.Close()
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = LoadDomainPopularityList(huge, "rank-domain", root); err == nil {
		t.Fatal("size")
	}
	var rows strings.Builder
	for i := 1; i <= MaxPopularityRows+1; i++ {
		rows.WriteString(strconv.Itoa(i))
		rows.WriteString(",example.com\n")
	}
	if _, _, err := LoadDomainPopularityList(popularityFile(t, rows.String()), "rank-domain", root); err == nil || !strings.Contains(err.Error(), "1000000") {
		t.Fatal("rows", err)
	}
	originalPath, originalConfig, old := DataBaseFolderPath, CurrentConfig, popularity.Load()
	t.Cleanup(func() { DataBaseFolderPath, CurrentConfig = originalPath, originalConfig; popularity.Store(old) })
	DataBaseFolderPath = root
	CurrentConfig = Config{}
	InitDNSWhitelist()
	if IsWhitelistedDomain("example.com") {
		t.Fatal("legacy file active")
	}
	external := popularityFile(t, "1,example.com\n")
	before, _ := os.ReadFile(external)
	CurrentConfig.DomainPopularityList = external
	InitDNSWhitelist()
	if !IsWhitelistedDomain("example.com") {
		t.Fatal("explicit list inactive")
	}
	// Simulate core database replacement; external operator data survives byte-for-byte.
	if err := os.RemoveAll(root); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	InitDNSWhitelist()
	after, _ := os.ReadFile(external)
	if string(before) != string(after) || !IsWhitelistedDomain("example.com") {
		t.Fatal("core update changed user list")
	}
	CurrentConfig.DomainPopularityList = ""
	CurrentConfig.DisableDomainPopularity = true
	InitDNSWhitelist()
	if IsWhitelistedDomain("example.com") {
		t.Fatal("disabled list retained entries")
	}
}

func TestPopularityNormalizedPathsAreReadOnly(t *testing.T) {
	base := t.TempDir()
	originalRoot := ConfigRootPath
	ConfigRootPath = filepath.Join(base, "uncreated-config")
	t.Cleanup(func() { ConfigRootPath = originalRoot })
	managed := filepath.Join(base, "dbs")
	if err := os.Mkdir(managed, 0700); err != nil {
		t.Fatal(err)
	}
	external := filepath.Join(base, "operator.csv")
	data := []byte("1,example.com\n")
	if err := os.WriteFile(external, data, 0400); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(external)
	if err != nil {
		t.Fatal(err)
	}
	configBefore, rootBefore := CurrentConfig, ConfigRootPath
	lexicalInside := filepath.Join(managed, "outward.csv")
	if err := os.Symlink(external, lexicalInside); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadDomainPopularityList(lexicalInside, "rank-domain", managed); err == nil {
		t.Fatal("managed symlink to external file would lose its configured path on update")
	}
	normalizedInside := managed + string(filepath.Separator) + ".." + string(filepath.Separator) + "dbs" + string(filepath.Separator) + "outward.csv"
	if _, _, err := LoadDomainPopularityList(normalizedInside, "rank-domain", managed); err == nil {
		t.Fatal("normalized managed path accepted")
	}
	alias := filepath.Join(base, "root-alias")
	if err := os.Symlink(base, alias); err != nil {
		t.Fatal(err)
	}
	missingManaged := filepath.Join(alias, "absent", "dbs")
	if _, err := ExternalPopularityPath(filepath.Join(base, "absent", "dbs", "list.csv"), missingManaged); err == nil {
		t.Fatal("missing managed ancestor alias bypass")
	}
	for _, path := range []string{external, base + "/not-created/../operator.csv", filepath.Join(alias, "operator.csv")} {
		list, _, err := LoadDomainPopularityList(path, "rank-domain", managed)
		if err != nil || !list.ContainsDNS("example.com") {
			t.Fatal(path, err)
		}
	}
	after, err := os.Stat(external)
	if err != nil {
		t.Fatal(err)
	}
	bytes, err := os.ReadFile(external)
	if err != nil {
		t.Fatal(err)
	}
	if string(bytes) != string(data) || !os.SameFile(before, after) || before.Mode() != after.Mode() || !before.ModTime().Equal(after.ModTime()) {
		t.Fatal("loader wrote the operator file")
	}
	if CurrentConfig != configBefore || ConfigRootPath != rootBefore {
		t.Fatal("loader mutated resolver configuration")
	}
	for _, absent := range []string{ConfigRootPath, filepath.Join(base, "absent"), filepath.Join(base, "not-created")} {
		if _, err := os.Stat(absent); !os.IsNotExist(err) {
			t.Fatal("loader created a path", absent, err)
		}
	}
}
