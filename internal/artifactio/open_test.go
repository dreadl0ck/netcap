package artifactio

import (
	"context"
	"io"
	"math"
	"os"
	"path/filepath"
	"sync"
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

func TestMaximumReadLimitDoesNotOverflow(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "data"), []byte("evidence"), 0600); err != nil {
		t.Fatal(err)
	}
	got, err := Read(context.Background(), root, "data", math.MaxInt64)
	if err != nil || string(got) != "evidence" {
		t.Fatalf("got %q: %v", got, err)
	}
}

func TestDescriptorSurvivesRootReplacement(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "root")
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "data"), []byte("owned evidence"), 0600); err != nil {
		t.Fatal(err)
	}
	f, _, err := Open(root, "data")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := os.Rename(root, filepath.Join(parent, "old-root")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "data"), []byte("replacement sentinel"), 0600); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(f)
	if err != nil || string(got) != "owned evidence" {
		t.Fatalf("descriptor rebound: %q %v", got, err)
	}
}

func TestConcurrentSymlinkReplacementCannotDiscloseSentinel(t *testing.T) {
	root := t.TempDir()
	outside := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(outside, []byte("private sentinel"), 0600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "data")
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			_ = os.Remove(path)
			_ = os.Symlink(outside, path)
			_ = os.Remove(path)
			_ = os.WriteFile(path, []byte("public"), 0600)
		}
	}()
	defer func() { close(stop); wg.Wait() }()
	for range 500 {
		got, err := Read(context.Background(), root, "data", 100)
		if err == nil && string(got) != "public" && len(got) != 0 {
			t.Fatalf("disclosed bytes %q", got)
		}
	}
}
