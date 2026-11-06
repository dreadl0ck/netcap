package vulndb

import (
	"path/filepath"
	"testing"
)

func leaf(criteria string) Configuration {
	return Configuration{Nodes: []Node{{Operator: "OR", Matches: []CPEMatch{{Criteria: criteria, Vulnerable: true}}}}}
}

func TestCPEApplicabilityRejectsReportFalsePositives(t *testing.T) {
	path := filepath.Join(t.TempDir(), FileName)
	b, err := Create(path)
	if err != nil {
		t.Fatal(err)
	}
	entries := []Vulnerability{
		{ID: "IE-real", Description: "Internet Explorer vulnerability", Configurations: []Configuration{leaf("cpe:2.3:a:microsoft:internet_explorer:8.0:*:*:*:*:*:*:*")}},
		{ID: "IE-kernel", Description: "IE 8.0 information element vulnerability", Versions: []string{"8.0"}, Configurations: []Configuration{leaf("cpe:2.3:o:linux:linux_kernel:8.0:*:*:*:*:*:*:*")}},
		{ID: "apache-cassandra", Description: "Apache 2.2.15", Configurations: []Configuration{leaf("cpe:2.3:a:apache:cassandra:2.2.15:*:*:*:*:*:*:*")}},
		{ID: "apache-http", Description: "Apache HTTP", Configurations: []Configuration{leaf("cpe:2.3:a:apache:http_server:2.2.15:*:*:*:*:*:*:*")}},
		{ID: "nginx-ingress", Description: "nginx 1.10.3", Configurations: []Configuration{leaf("cpe:2.3:a:kubernetes:ingress-nginx:1.10.3:*:*:*:*:*:*:*")}},
		{ID: "no-applicability", Description: "IE 8.0", Versions: []string{"8.0"}},
	}
	for _, v := range entries {
		if err := b.AddVulnerability(v); err != nil {
			t.Fatal(err)
		}
	}
	if err := b.AddExploit(Exploit{ID: "confirmed", Description: "Unrelated title", CVEs: []string{"IE-real"}}); err != nil {
		t.Fatal(err)
	}
	if err := b.AddExploit(Exploit{ID: "text-only", Description: "IE 8.0 exploit"}); err != nil {
		t.Fatal(err)
	}
	if err := b.Finish(); err != nil {
		t.Fatal(err)
	}
	db, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, tc := range []struct{ vendor, product, version, want string }{{"", "IE", "8.0", "IE-real"}, {"Apache", "Apache", "2.2.15", "apache-http"}, {"", "nginx", "1.10.3", ""}, {"Linux", "IE", "8.0", ""}} {
		got, err := db.Vulnerabilities(tc.vendor, tc.product, tc.version)
		if err != nil {
			t.Fatal(err)
		}
		if tc.want == "" {
			if len(got) != 0 {
				t.Fatal("false product match", got)
			}
		} else if len(got) != 1 || got[0].ID != tc.want {
			t.Fatal(tc, got)
		}
	}
	e, err := db.Exploits("", "IE", "8.0")
	if err != nil || len(e) != 1 || e[0].ID != "confirmed" {
		t.Fatal(e, err)
	}
}

func TestRangesAndEnvironmentalConditions(t *testing.T) {
	id := Identity{"a", "apache", "http_server", "2.4.50"}
	m := CPEMatch{Criteria: "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*", Vulnerable: true, StartIncluding: "2.4.49", EndExcluding: "2.4.51"}
	c := Configuration{Nodes: []Node{{Operator: "OR", Matches: []CPEMatch{m}}}}
	if !applicable([]Configuration{c}, id) {
		t.Fatal("inclusive start/exclusive end interval lost")
	}
	id.Version = "2.4.51"
	if applicable([]Configuration{c}, id) {
		t.Fatal("excluded upper bound matched")
	}
	id.Version = "2.4.50"
	c.Nodes[0].Operator = "AND"
	c.Nodes[0].Matches = append(c.Nodes[0].Matches, CPEMatch{Criteria: "cpe:2.3:o:microsoft:windows_10:*:*:*:*:*:*:*:*"})
	if applicable([]Configuration{c}, id) {
		t.Fatal("unobserved OS requirement claimed as satisfied")
	}
	c.Nodes[0].Negate = true
	if applicable([]Configuration{c}, id) {
		t.Fatal("negation produced an affected product")
	}
	if _, ok := compareVersion("2.4.50rc1", "2.4.51"); ok {
		t.Fatal("guessed ordering for non-numeric version")
	}
}
