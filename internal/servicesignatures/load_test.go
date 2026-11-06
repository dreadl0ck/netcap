package servicesignatures

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadRejectsNonRegularCatalogue(t *testing.T) {
	dir := t.TempDir()
	regular := filepath.Join(dir, "regular.json")
	if err := os.WriteFile(regular, builtin, 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.json")
	if err := os.Symlink(regular, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	for _, path := range []string{link, dir} {
		e, err := Load(path)
		if err == nil || e == nil || e.sourceSHA256 != Builtin().sourceSHA256 {
			t.Fatalf("%s: expected visible built-in fallback, got %v", path, err)
		}
	}
}

func TestCatalogueAndBannerLimitBoundaries(t *testing.T) {
	for _, extra := range []int{0, 1} {
		b := append(bytes.Clone(builtin), bytes.Repeat([]byte{' '}, MaxCatalogueBytes-len(builtin)+extra)...)
		path := filepath.Join(t.TempDir(), FileName)
		if err := os.WriteFile(path, b, 0600); err != nil {
			t.Fatal(err)
		}
		e, err := Load(path)
		if (err == nil) != (extra == 0) || e == nil {
			t.Fatalf("catalogue bytes %d: %v", len(b), err)
		}
	}
	for _, size := range []int{MaxBannerBytes, MaxBannerBytes + 1} {
		banner := append([]byte("HTTP/1.1 200 "), bytes.Repeat([]byte{'x'}, size-15)...)
		banner = append(banner, '\r', '\n')
		if len(banner) != size {
			t.Fatal("invalid boundary fixture")
		}
		_, ok := Builtin().Identify(banner, "tcp", "server-to-client")
		if ok != (size == MaxBannerBytes) {
			t.Fatalf("banner bytes %d: matched=%v", size, ok)
		}
	}
}

func TestLoadThroughManagedDirectory(t *testing.T) {
	dir := t.TempDir()
	release := filepath.Join(dir, "release")
	if err := os.Mkdir(release, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(release, FileName), builtin, 0600); err != nil {
		t.Fatal(err)
	}
	active := filepath.Join(dir, "dbs")
	if err := os.Symlink(release, active); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	e, err := Load(filepath.Join(active, FileName))
	if err != nil || e.sourceSHA256 != Builtin().sourceSHA256 {
		t.Fatalf("managed directory cannot load a regular catalogue: %v", err)
	}
}
