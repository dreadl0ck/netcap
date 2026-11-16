package webui

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSchemaAdmissionRejectsBroadSourcesBeforeTraversal(t *testing.T) {
	for _, path := range []string{"/etc", "/", "/dev", ".", "/does-not-exist/private-sentinel"} {
		if _, err := admitSchemaSearchPath(path); err == nil || strings.Contains(err.Error(), "private-sentinel") || strings.Contains(err.Error(), "permission denied") {
			t.Fatalf("unexpected admission: %s %v", path, err)
		}
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "fixture.proto")
	if err := os.WriteFile(path, []byte(`syntax = "proto3"; message Fixture { string value = 1; }`), 0600); err != nil {
		t.Fatal(err)
	}
	for _, source := range []string{dir, path} {
		if _, err := admitSchemaSearchPath(source); err != nil {
			t.Fatal(source, err)
		}
	}
	link := filepath.Join(t.TempDir(), "linked.proto")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := admitSchemaSearchPath(link); err == nil {
		t.Fatal("symlink admitted")
	}
	for i := range 257 {
		if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("file-%d.proto", i)), []byte(`syntax = "proto3";`), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := admitSchemaSearchPath(dir); err == nil {
		t.Fatal("schema file bound not enforced")
	}
}
