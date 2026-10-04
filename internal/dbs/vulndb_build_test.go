package dbs

import (
	"compress/gzip"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/internal/vulndb"
)

const nvdFixture = `{"resultsPerPage":2,"format":"NVD_CVE","version":"2.0","vulnerabilities":[
{"cve":{"id":"CVE-2021-41773","descriptions":[{"lang":"es","value":"x"},{"lang":"en","value":"Apache HTTP Server 2.4.49 path traversal"}],
 "metrics":{"cvssMetricV2":[{"cvssData":{"baseScore":4.3,"accessVector":"NETWORK","accessComplexity":"MEDIUM"},"baseSeverity":"MEDIUM"}]},
 "configurations":[{"nodes":[{"operator":"OR","cpeMatch":[{"vulnerable":true,"criteria":"cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"}]}]}]}},
{"cve":{"id":"CVE-2020-1","descriptions":[{"lang":"en","value":"Example 1.2.3 bug"}],"metrics":{}}},
{"cve":{"id":"CVE-2020-2","descriptions":[{"lang":"de","value":"no english"}]}}
]}`

const exploitFixture = "id,file,description,date_published,author,type,platform,port\n" +
	"50383,exploits/multiple/webapps/50383.sh,\"Apache HTTP Server 2.4.49 - Path Traversal\",2021-10-06,Lucas Souza,webapps,multiple,\n"

func writeGz(t *testing.T, path, content string) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	zw := gzip.NewWriter(f)
	if _, err = zw.Write([]byte(content)); err != nil {
		t.Fatal(err)
	}
	zw.Close()
	f.Close()
}

func TestBuildVulnDBFromFeeds(t *testing.T) {
	build, out := t.TempDir(), t.TempDir()
	year := time.Now().Year()
	// only the newest year exists: older years are logged and skipped
	writeGz(t, filepath.Join(build, "nvdcve-2.0-"+strconv.Itoa(year)+".json.gz"), nvdFixture)
	if err := os.WriteFile(filepath.Join(build, "files_exploits.csv"), []byte(exploitFixture), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := BuildVulnDB(build, out, year-2, false); err != nil {
		t.Fatal(err)
	}
	d, err := vulndb.Open(filepath.Join(out, vulndb.FileName))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	meta, _ := d.Meta()
	if meta["nvd_count"] != "2" || meta["exploit_count"] != "1" {
		t.Fatalf("meta %v", meta)
	}
	v, err := d.Vulnerabilities("Apache", "HTTP Server", "2.4.49")
	if err != nil || len(v) != 1 || v[0].V2Score != "4.3" || v[0].AttackComplexity != "MEDIUM" {
		t.Fatalf("%+v %v", v, err)
	}
	// version taken from the description when no CPE carries one
	if v, _ = d.Vulnerabilities("Example", "", "1.2.3"); len(v) != 1 {
		t.Fatalf("description version: %+v", v)
	}
	e, err := d.Exploits("Apache", "", "2.4.49")
	if err != nil || len(e) != 1 || e[0].Date != "2021-10-06" || e[0].Author != "Lucas Souza" {
		t.Fatalf("%+v %v", e, err)
	}
}

func TestBuildVulnDBRefusesEmptyFeeds(t *testing.T) {
	out := t.TempDir()
	if err := BuildVulnDB(t.TempDir(), out, time.Now().Year()-1, false); err == nil {
		t.Fatal("built a database without NVD entries")
	}
	if _, err := os.Stat(filepath.Join(out, vulndb.FileName)); !os.IsNotExist(err) {
		t.Fatal("a failed build left a database behind")
	}
}
