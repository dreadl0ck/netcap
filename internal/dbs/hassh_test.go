package dbs

import (
	"os"
	"path/filepath"
	"testing"
)

func TestHASSHConversionRejectsInvalidDataAndPreservesLikelihood(t *testing.T) {
	base := t.TempDir()
	if err := os.Mkdir(filepath.Join(base, "dbs"), 0o755); err != nil {
		t.Fatal(err)
	}
	in := filepath.Join(base, "input")
	data := "004238f88dc63904baf2d5cf128db12f SSH-2.0-fixture (100+)\n"
	if err := os.WriteFile(in, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	s := &datasource{name: "hasshdb.json"}
	if err := convertHASSH(in, s, base); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(base, "dbs", s.name))
	if err != nil || string(b) != `[{"hash":"004238f88dc63904baf2d5cf128db12f","softwares":[{"name":"SSH-2.0-fixture","likelyhood":"100+"}]}]` {
		t.Fatalf("%s %v", b, err)
	}
	for _, bad := range []string{data + data, "invalid SSH-2.0-test (100)\n", "004238f88dc63904baf2d5cf128db12f SSH-2.0-test (101)\n"} {
		if err := os.WriteFile(in, []byte(bad), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := convertHASSH(in, s, base); err == nil {
			t.Fatal("accepted invalid upstream catalogue")
		}
	}
}
