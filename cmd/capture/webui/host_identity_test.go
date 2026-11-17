package webui

import (
	"context"
	"encoding/json"
	"net/http/httptest"
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

func TestHostIdentityPagesWithoutTrafficAndInvalidateOnIdentityChange(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "Hosts.json")
	data := `{"schema":1,"hosts":[{"scope":"one","ip":"10.0.0.1","hostnameState":"ambiguous","macState":"unknown","accounts":[{"at":1700000000000000001,"name":"alice"}]},{"scope":"two","ip":"10.0.0.1","hostnameState":"observed","macState":"unknown"}],"directory":[{"scope":"one","account":"unattached","evidence":{"at":1700000000000000002}}],"overflow":2}`
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	s := &Server{outDir: dir}
	read := func(query string) (int, map[string]json.RawMessage) {
		w := httptest.NewRecorder()
		s.handleHosts(w, httptest.NewRequest("GET", "/api/hosts?mcpPage=true&pageLimit=1&"+query, nil))
		var result map[string]json.RawMessage
		if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
			t.Fatal(w.Body.String(), err)
		}
		return w.Code, result
	}
	for _, view := range []string{"traffic", "identity", "directory"} {
		code, page := read("view=" + view)
		if code != 200 || len(page["identity"]) == 0 {
			t.Fatal(view, code, page)
		}
		var rows []map[string]any
		if err := json.Unmarshal(page["hosts"], &rows); err != nil {
			t.Fatal(err)
		}
		if view == "traffic" && len(rows) != 0 {
			t.Fatal("invented traffic row")
		}
		if view != "traffic" && len(rows) != 1 {
			t.Fatal("identity evidence lost", view, rows)
		}
		if view == "identity" {
			code, second := read("view=identity&pageOffset=1")
			if code != 200 || string(second["hosts"]) == string(page["hosts"]) {
				t.Fatal("scoped identities collapsed", second)
			}
		}
		var generation string
		json.Unmarshal(page["generation"], &generation)
		changed := strings.Replace(data, `"overflow":2`, `"overflow":3`, 1)
		if err := os.WriteFile(path, []byte(changed), 0600); err != nil {
			t.Fatal(err)
		}
		if code, _ := read("view=" + view + "&pageGeneration=" + generation); code != 409 {
			t.Fatal("identity change did not invalidate continuation", view, code)
		}
		if err := os.WriteFile(path, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
}
