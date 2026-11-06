package dbs

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/internal/vulndb"
)

const referenceFixture = `{"vulnerabilities":[{"cve":{"id":"CVE-2026-99999","descriptions":[{"lang":"en","value":"Synthetic reference-product 1.2.3 bug"}],"references":[
{"url":"https://example.org/advisory?q=1&b=2","source":"vendor\"@example.org","tags":["Vendor Advisory","Exploit"]},
{"url":"http://example.org/poc","source":"nvd@nist.gov"},
{"url":"https://example.org/advisory?q=1&b=2","source":"vendor\"@example.org","tags":["Exploit","Patch"]},
{"url":"https://example.org/advisory?q=1&b=2","source":"other","tags":["Third Party Advisory"]},
{"url":"javascript:alert(1)"},{"url":"ftp://example.org/poc"},{"url":"/relative"},
{"url":"https://"},{"url":"https://example.org/%zz"},{"url":"https://example.org/\ncontrol"},
{"url":"https://example.org/?q=%zz"},{"url":"https://example.org:99999/poc"},
{"url":"https://example.org/\u007fcontrol"},{"url":"https://example.org/a b"},
{"url":"https://user:pass@example.org/poc"}
],"configurations":[{"nodes":[{"operator":"OR","cpeMatch":[{"vulnerable":true,"criteria":"cpe:2.3:a:test:reference-product:1.2.3:*:*:*:*:*:*:*"}]}]}]}}]}`

func TestNVDReferencesBuildAndDeterminism(t *testing.T) {
	build, out := t.TempDir(), t.TempDir()
	year := time.Now().Year()
	writeGz(t, filepath.Join(build, "nvdcve-2.0-"+strconv.Itoa(year)+".json.gz"), referenceFixture)
	var previous []byte
	for range 2 {
		if err := BuildVulnDB(build, out, year, false); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(out, vulndb.FileName)
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if previous != nil && !bytes.Equal(previous, data) {
			t.Fatal("identical inputs changed SQLite bytes")
		}
		previous = data
		d, err := vulndb.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		meta, err := d.Meta()
		if err != nil || meta["schema_version"] != strconv.Itoa(vulndb.SchemaVersion) || meta["nvd_rowid_alias_version"] != "1" || meta["nvd_references_version"] != "1" || meta["nvd_count"] != "1" || meta["exploit_count"] != "0" {
			t.Fatalf("meta: %v %v", meta, err)
		}
		v, err := d.Vulnerabilities("test", "reference-product", "1.2.3")
		if err != nil || len(v) != 1 {
			t.Fatalf("lookup: %+v %v", v, err)
		}
		want := []vulndb.Reference{
			{URL: "http://example.org/poc", Source: "nvd@nist.gov", Tags: []string{}},
			{URL: "https://example.org/advisory?q=1&b=2", Source: "other", Tags: []string{"Third Party Advisory"}},
			{URL: "https://example.org/advisory?q=1&b=2", Source: "vendor\"@example.org", Tags: []string{"Exploit", "Patch", "Vendor Advisory"}},
		}
		if !reflect.DeepEqual(v[0].References, want) {
			t.Fatalf("references: %+v", v[0].References)
		}
		encoded, err := json.Marshal(v[0].References)
		if err != nil || !json.Valid(encoded) {
			t.Fatalf("invalid reference JSON: %s %v", encoded, err)
		}
		if e, err := d.Exploits("", "reference-product", "1.2.3"); err != nil || len(e) != 0 {
			t.Fatalf("unexpected exploits: %v %v", e, err)
		}
		d.Close()
		conn, err := sql.Open("sqlite", path)
		if err != nil {
			t.Fatal(err)
		}
		rows, err := conn.Query(`PRAGMA foreign_key_check`)
		if err != nil {
			t.Fatal(err)
		}
		if rows.Next() {
			t.Fatal("foreign_key_check returned a violation in NVD-built database")
		}
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
		rows.Close()
		var versions int
		if err := conn.QueryRow(`SELECT count(*) FROM nvd_versions v JOIN nvd n ON n.rowid=v.nvd_rowid AND n.nvd_rowid=n.rowid`).Scan(&versions); err != nil || versions != 1 {
			t.Fatalf("version rowid join: %d %v", versions, err)
		}
		conn.Close()
	}
	// Optional cross-language test input; generated only when explicitly requested.
	if path := os.Getenv("NETCAP_REFERENCE_FIXTURE_OUT"); path != "" {
		if err := os.WriteFile(path, previous, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}
