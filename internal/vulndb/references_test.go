package vulndb

import (
	"bytes"
	"database/sql"
	"os"
	"path/filepath"
	"testing"
)

func TestReferenceOrderDoesNotChangeDatabase(t *testing.T) {
	refs := []Reference{
		{URL: "https://example.org/z", Source: "nvd", Tags: []string{"Patch", "Exploit", "Patch"}},
		{URL: "http://example.org/a", Tags: []string{}},
		{URL: "https://example.org/z", Source: "nvd", Tags: []string{"Vendor Advisory"}},
	}
	var previous []byte
	for round := range 2 {
		path := filepath.Join(t.TempDir(), FileName)
		b, err := Create(path)
		if err != nil {
			t.Fatal(err)
		}
		if round == 1 {
			refs[0], refs[2] = refs[2], refs[0]
		}
		v := Vulnerability{ID: "CVE-one", Description: "product 1.0", Versions: []string{"1.0"}, References: refs}
		if err := b.AddVulnerability(v); err != nil {
			t.Fatal(err)
		}
		// Repeated CVEs keep the first full entry, including its references.
		v.References = []Reference{{URL: "https://ignored.example.org/"}}
		if err := b.AddVulnerability(v); err != nil {
			t.Fatal(err)
		}
		if n, e := b.Counts(); n != 1 || e != 0 {
			t.Fatalf("counts %d %d", n, e)
		}
		if err := b.Finish(); err != nil {
			t.Fatal(err)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if previous != nil && !bytes.Equal(previous, data) {
			t.Fatal("reference order changed database bytes")
		}
		previous = data
	}
}

func TestReferencesOptionalSchemaOne(t *testing.T) {
	for _, mode := range []string{"old", "missing-table", "unknown-version"} {
		t.Run(mode, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), FileName)
			b, err := Create(path)
			if err != nil {
				t.Fatal(err)
			}
			if err := b.AddVulnerability(Vulnerability{ID: "CVE-test", Description: "product 1.0", Versions: []string{"1.0"}, References: []Reference{{URL: "https://example.org/", Tags: []string{"Exploit"}}}}); err != nil {
				t.Fatal(err)
			}
			if err := b.Finish(); err != nil {
				t.Fatal(err)
			}
			w, err := sql.Open("sqlite", path)
			if err != nil {
				t.Fatal(err)
			}
			query := `DROP TABLE nvd_references; DELETE FROM meta WHERE key='nvd_references_version'`
			if mode == "missing-table" {
				query = `DROP TABLE nvd_references`
			}
			if mode == "unknown-version" {
				query = `UPDATE meta SET value='99' WHERE key='nvd_references_version'`
			}
			if _, err := w.Exec(query); err != nil {
				t.Fatal(err)
			}
			w.Close()
			d, err := Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer d.Close()
			v, err := d.Vulnerabilities("", "product", "1.0")
			if err != nil || len(v) != 1 || v[0].References == nil || len(v[0].References) != 0 {
				t.Fatalf("%+v %v", v, err)
			}
		})
	}
}
