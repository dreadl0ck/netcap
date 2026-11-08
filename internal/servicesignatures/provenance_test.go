package servicesignatures

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"testing"
)

func TestPublishableCatalogueAndProvenanceBinding(t *testing.T) {
	b, err := os.ReadFile(FileName)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(b, builtin) {
		t.Fatal("separate catalogue changed stable builtins")
	}
	p, err := os.ReadFile("provenance.json")
	if err != nil {
		t.Fatal(err)
	}
	var review struct {
		Catalogue struct {
			SHA256              string
			HumanRightsApproval bool `json:"human_rights_approval"`
		}
		Rules    []struct{ ID string }
		Fixtures struct {
			Count         int
			ReviewedNames []string `json:"reviewed_names"`
		}
		Validation struct {
			Count         int
			ReviewedNames []string `json:"reviewed_names"`
		}
	}
	if err = json.Unmarshal(p, &review); err != nil {
		t.Fatal(err)
	}
	if review.Catalogue.SHA256 != fmt.Sprintf("%x", sha256.Sum256(b)) || review.Catalogue.HumanRightsApproval {
		t.Fatal("invalid automated provenance binding")
	}
	if len(review.Rules) != 4 || review.Fixtures.Count != 14 || len(review.Fixtures.ReviewedNames) != 14 || review.Validation.Count != 17 || len(review.Validation.ReviewedNames) != 17 {
		t.Fatal("incomplete review map")
	}
	for i, r := range Builtin().Catalogue().Rules {
		if review.Rules[i].ID != r.ID {
			t.Fatal("rule review mapping")
		}
	}
}
