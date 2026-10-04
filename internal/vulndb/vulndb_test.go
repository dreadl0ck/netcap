package vulndb

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func build(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), FileName)
	b, err := Create(path)
	if err != nil {
		t.Fatal(err)
	}
	b.SetMeta("nvd_start_year", "2002")
	vulns := []Vulnerability{
		{ID: "CVE-2021-41773", Description: "A flaw in Apache HTTP Server 2.4.49 allows path traversal.", Severity: "HIGH", V2Score: "4.3", AccessVector: "NETWORK", BaseScore: 4.3, Versions: []string{"2.4.49"}},
		{ID: "CVE-2021-42013", Description: "Apache HTTP Server 2.4.50 incomplete fix of CVE-2021-41773.", Severity: "HIGH", Versions: []string{"2.4.49", "2.4.50"}},
		{ID: "CVE-2020-0001", Description: "nginx before 1.17.7 request smuggling.", Versions: []string{"1.17.6"}},
		{ID: "CVE-2021-41773", Description: "duplicate id is ignored", Versions: []string{"9.9"}},
	}
	for _, v := range vulns {
		if err := b.AddVulnerability(v); err != nil {
			t.Fatal(err)
		}
	}
	for _, e := range []Exploit{
		{ID: "50383", File: "exploits/multiple/webapps/50383.sh", Description: "Apache HTTP Server 2.4.49 - Path Traversal & Remote Code Execution (RCE)", Date: "2021-10-06", Author: "Lucas Souza", Type: "webapps", Platform: "multiple"},
		{ID: "1", File: "exploits/x.c", Description: "OpenSSH 7.2 \"quoted\" username enumeration"},
	} {
		if err := b.AddExploit(e); err != nil {
			t.Fatal(err)
		}
	}
	if n, e := b.Counts(); n != 3 || e != 2 {
		t.Fatalf("counts %d %d", n, e)
	}
	if err := b.Finish(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Fatal("temporary file left behind")
	}
	return path
}

func ids[T any](items []T, id func(T) string) []string {
	out := []string{}
	for _, it := range items {
		out = append(out, id(it))
	}
	return out
}

func TestLookups(t *testing.T) {
	d, err := Open(build(t))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	meta, _ := d.Meta()
	if meta["nvd_count"] != "3" || meta["nvd_start_year"] != "2002" || meta["schema_version"] != "1" {
		t.Fatalf("meta %v", meta)
	}
	vid := func(v Vulnerability) string { return v.ID }
	cases := []struct {
		vendor, product, version string
		want                     []string
	}{
		{"Apache", "HTTP Server", "2.4.49", []string{"CVE-2021-41773", "CVE-2021-42013"}},
		{"apache", "", "2.4.50", []string{"CVE-2021-42013"}},
		{"Apache", "HTTP Server", "2.4", []string{}}, // versions match exactly
		{"", "", "2.4.49", []string{}},               // a text term is required
		{"Apache", "nginx", "2.4.49", []string{}},    // every term is required
		{"nginx", "", "1.17.6", []string{"CVE-2020-0001"}},
	}
	for _, c := range cases {
		got, err := d.Vulnerabilities(c.vendor, c.product, c.version)
		if err != nil {
			t.Fatal(err)
		}
		if g := ids(got, vid); !reflect.DeepEqual(g, c.want) {
			t.Errorf("%q %q %q: got %v want %v", c.vendor, c.product, c.version, g, c.want)
		}
	}
	got, _ := d.Vulnerabilities("Apache", "", "2.4.49")
	if got[0].ID != "CVE-2021-41773" || got[0].Severity != "HIGH" || got[0].BaseScore != 4.3 || got[0].AccessVector != "NETWORK" {
		t.Errorf("fields: %+v", got[0])
	}

	eid := func(e Exploit) string { return e.ID }
	for _, c := range []struct {
		vendor, product, version string
		want                     []string
	}{
		{"Apache", "HTTP Server", "2.4.49", []string{"50383"}},
		{"Apache", "HTTP Server", "2.4.50", []string{}},
		{"OpenSSH", `"quoted"`, "7.2", []string{"1"}}, // quotes are escaped
		{"", "...", "", []string{}},                   // punctuation-only terms are dropped
	} {
		got, err := d.Exploits(c.vendor, c.product, c.version)
		if err != nil {
			t.Fatal(err)
		}
		if g := ids(got, eid); !reflect.DeepEqual(g, c.want) {
			t.Errorf("exploit %q %q %q: got %v want %v", c.vendor, c.product, c.version, g, c.want)
		}
	}
}

func TestOpenRejectsOtherFiles(t *testing.T) {
	if _, err := Open(filepath.Join(t.TempDir(), "missing.sqlite")); err == nil {
		t.Fatal("missing file opened")
	}
	bad := filepath.Join(t.TempDir(), "bad.sqlite")
	if err := os.WriteFile(bad, []byte("not sqlite"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(bad); !errors.Is(err, ErrSchema) {
		t.Fatalf("got %v", err)
	}
}

func TestMatchExpr(t *testing.T) {
	if got := MatchExpr(" Apache ", "", `a"b`, "-"); got != `"Apache" AND "a""b"` {
		t.Fatal(got)
	}
}
