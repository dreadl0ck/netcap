package publication

import (
	"bytes"
	"encoding/json"
	"github.com/dreadl0ck/netcap/internal/enrichment"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOptionalSourcePolicyBindsFullScopedGrants(t *testing.T) {
	members, err := Members()
	if err != nil {
		t.Fatal(err)
	}
	for name, want := range members {
		got, err := os.ReadFile(filepath.Join("catalogues", name))
		if err != nil || !bytes.Equal(got, want) {
			t.Fatal("staged source policy or catalogue drift", name, err)
		}
	}
	var sources []enrichment.Source
	if err = json.Unmarshal(members[enrichment.SourcesName], &sources); err != nil {
		t.Fatal(err)
	}
	if len(sources) != 2 {
		t.Fatal("missing optional source")
	}
	for _, s := range sources {
		if s.Review == nil || s.Review.EvidenceSHA256 != enrichment.Digest([]byte(s.Evidence)) || !strings.Contains(s.Review.Reviewer, "automated AI") || !strings.Contains(s.Review.Authorization, "to the extent owned") {
			t.Fatal("missing accurate automated review")
		}
		if enrichment.Digest([]byte(s.GrantText)) != s.GrantSHA256 || !strings.Contains(string(members[enrichment.NoticesName]), s.GrantText) {
			t.Fatal("unbound full grant")
		}
		for _, o := range s.Outputs {
			if enrichment.Digest(members[o.Path]) != o.SHA256 || int64(len(members[o.Path])) != o.Size {
				t.Fatal("unbound output")
			}
		}
	}
	notices := string(members[enrichment.NoticesName])
	for _, text := range []string{"to the extent", "existing GPL", "daffainfo", "ricardomaia", "Copyright (c) 2025 ProjectDiscovery, Inc.", "THE SOFTWARE IS PROVIDED"} {
		if !strings.Contains(notices, text) {
			t.Fatal("missing scoped notice", text)
		}
	}
	dir := t.TempDir()
	for name, b := range members {
		if err = os.WriteFile(filepath.Join(dir, name), b, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, err = enrichment.Pack(dir); err != nil {
		t.Fatal(err)
	}
}
