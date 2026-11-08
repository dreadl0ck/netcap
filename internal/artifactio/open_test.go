package artifactio

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestConfinedArtifacts(t *testing.T) {
	root := t.TempDir()
	outside := filepath.Join(t.TempDir(), "sentinel")
	if err := os.WriteFile(outside, []byte("private sentinel"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "nested"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "nested", "ok"), []byte("public"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Dir(outside), filepath.Join(root, "dir-link")); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"../sentinel", outside, "link", "dir-link/sentinel", "nested/../link", "nested", "nested\\ok", ""} {
		if b, err := Read(context.Background(), root, path, 100); err == nil {
			t.Fatalf("unsafe path %q read %q", path, b)
		}
	}
	b, err := Read(context.Background(), root, "nested/ok", 100)
	if err != nil || string(b) != "public" {
		t.Fatalf("valid artifact: %q %v", b, err)
	}
	if _, err := Read(context.Background(), root, "nested/ok", 2); err == nil {
		t.Fatal("byte limit ignored")
	}
	alias := filepath.Join(t.TempDir(), "root-link")
	if err := os.Symlink(root, alias); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Open(alias, "nested/ok"); err == nil {
		t.Fatal("symlink extraction root accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Read(ctx, root, "nested/ok", 100); err == nil {
		t.Fatal("cancelled read succeeded")
	}
}
