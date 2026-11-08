package webui

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHostIdentityEvidence(t *testing.T) {
	dir := t.TempDir()
	missing, err := readHostIdentity(context.Background(), dir)
	if err != nil || missing.State != "unavailable" {
		t.Fatalf("missing: %+v %v", missing, err)
	}
	path := filepath.Join(dir, "Hosts.json")
	data := `{"schema":1,"hosts":[{"scope":"one","ip":"10.0.0.1","hostnameState":"ambiguous","macState":"unknown","accounts":[{"at":1700000000000000001,"name":"alice"}]},{"scope":"two","ip":"10.0.0.1","hostname":"other","hostnameState":"observed","macState":"unknown"}],"limitations":["capture scoped"],"overflow":3,"unscopedRecords":2}`
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	result, err := readHostIdentity(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"at":"1700000000000000001"`, `"scope":"one"`, `"scope":"two"`, `"hostnameState":"ambiguous"`, `"overflow":3`, `"capture scoped"`} {
		if !strings.Contains(string(b), want) {
			t.Fatalf("missing %s: %s", want, b)
		}
	}
	for _, bad := range []string{`null`, `{"schema":2,"hosts":[]}`, `{"schema":1,"hosts":{}}`, data + `{}`, `{`} {
		if err := os.WriteFile(path, []byte(bad), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := readHostIdentity(context.Background(), dir); err == nil {
			t.Fatalf("accepted %s", bad)
		}
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	external := filepath.Join(t.TempDir(), "identity.json")
	if err := os.WriteFile(external, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(external, path); err != nil {
		t.Fatal(err)
	}
	if _, err := readHostIdentity(context.Background(), dir); err == nil {
		t.Fatal("accepted symlink")
	}
}
