package webtech

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"testing"
)

func TestProvenanceBindsEveryDescriptorAndSyntheticVector(t *testing.T) {
	b, err := os.ReadFile("provenance.json")
	if err != nil {
		t.Fatal(err)
	}
	var p struct {
		CatalogueSHA256 string `json:"catalogue_sha256"`
		Fixtures        struct {
			SHA256 string
			Count  int
		}
		Rules []struct {
			ID            string
			Fixtures      []string
			License       string
			LicenseFile   string `json:"license_file"`
			LicenseSHA256 string `json:"license_sha256"`
		}
	}
	if err = json.Unmarshal(b, &p); err != nil {
		t.Fatal(err)
	}
	vectors, err := os.ReadFile("vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var cases []struct{ Name string }
	if err = json.Unmarshal(vectors, &cases); err != nil {
		t.Fatal(err)
	}
	if p.CatalogueSHA256 != fmt.Sprintf("%x", sha256.Sum256(descriptors)) || p.Fixtures.SHA256 != fmt.Sprintf("%x", sha256.Sum256(vectors)) || p.Fixtures.Count != len(cases) {
		t.Fatal("stale provenance")
	}
	e, err := Parse(descriptors)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Rules) != len(e.catalogue.Rules) {
		t.Fatal("missing provenance")
	}
	names := map[string]bool{}
	for _, c := range cases {
		names[c.Name] = true
	}
	for i, r := range p.Rules {
		if r.ID != e.catalogue.Rules[i].ID || len(r.Fixtures) == 0 {
			t.Fatal("missing rule review")
		}
		for _, name := range r.Fixtures {
			if !names[name] {
				t.Fatal("unknown fixture", name)
			}
		}
		if r.License != "" {
			license, e := os.ReadFile(r.LicenseFile)
			if e != nil || r.LicenseSHA256 != fmt.Sprintf("%x", sha256.Sum256(license)) {
				t.Fatal("license mismatch", e)
			}
		}
	}
}
