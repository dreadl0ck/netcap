package vulndb

import (
	"database/sql"
	"path/filepath"
	"testing"
)

func TestSchemaOneRowidAliasForeignKeys(t *testing.T) {
	path := filepath.Join(t.TempDir(), FileName)
	b, err := Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Abort()
	for _, id := range []string{"CVE-one", "CVE-two"} {
		if err := b.AddVulnerability(Vulnerability{ID: id, Description: "Example product 1.2.3", Versions: []string{"1.2.3", "1.2.4"}, References: []Reference{{URL: "https://example.org/"}}}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := b.tx.Exec(`INSERT INTO nvd_versions VALUES (99999, 'orphan')`); err == nil {
		t.Fatal("builder accepted orphan version")
	}
	if _, err := b.tx.Exec(`INSERT INTO nvd_references VALUES ('missing', 'https://example.org/', '', '[]')`); err == nil {
		t.Fatal("builder accepted orphan reference")
	}
	if err := b.Finish(); err != nil {
		t.Fatal(err)
	}
	w, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	rows, err := w.Query(`PRAGMA foreign_key_check`)
	if err != nil {
		t.Fatal(err)
	}
	if rows.Next() {
		t.Fatal("foreign_key_check returned a violation")
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	rows.Close()
	var count int
	for query, want := range map[string]int{
		`SELECT count(*) FROM nvd WHERE rowid = nvd_rowid`:                                                 2,
		`SELECT count(*) FROM nvd_versions v LEFT JOIN nvd n ON n.rowid=v.nvd_rowid WHERE n.id IS NULL`:    0,
		`SELECT count(*) FROM nvd_versions`:                                                                4,
		`SELECT count(*) FROM nvd_references`:                                                              2,
		`SELECT count(*) FROM nvd_fts JOIN nvd n ON n.rowid=nvd_fts.rowid WHERE nvd_fts MATCH '"Example"'`: 2,
	} {
		if err := w.QueryRow(query).Scan(&count); err != nil || count != want {
			t.Fatalf("%s: %d want %d: %v", query, count, want, err)
		}
	}
	d, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	meta, err := d.Meta()
	if err != nil || meta["schema_version"] != "1" || meta["nvd_rowid_alias_version"] != "1" {
		t.Fatalf("meta: %v %v", meta, err)
	}
	v, err := d.Vulnerabilities("Example", "product", "1.2.3")
	if err != nil || len(v) != 2 || len(v[0].References) != 1 {
		t.Fatalf("query: %+v %v", v, err)
	}
}
