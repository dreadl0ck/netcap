package dbs

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestGeneratedDatabaseArchiveIncludesNotices(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "dbs")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := writeDatabaseNotices(dir); err != nil {
		t.Fatal(err)
	}

	var archive bytes.Buffer
	if err := makeTarball(dir, "dbs", &archive); err != nil {
		t.Fatal(err)
	}
	zr, err := gzip.NewReader(&archive)
	if err != nil {
		t.Fatal(err)
	}
	defer zr.Close()
	tr := tar.NewReader(zr)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			t.Fatal("database archive omitted notices")
		}
		if err != nil {
			t.Fatal(err)
		}
		if h.Name == "dbs/DATABASE_NOTICES.txt" {
			body, err := io.ReadAll(tr)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(body, databaseNotices) {
				t.Fatal("database archive contains different notices")
			}
			return
		}
	}
}

func TestPackedDatabaseArchiveIncludesNotices(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "dbs")
	out := filepath.Join(root, "release")
	for _, path := range []string{dir, out} {
		if err := os.Mkdir(path, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "sample.json"), []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command("bash", "../../zeus/scripts/pack-dbs.sh", "-d", dir, "-o", out, "-v", "2026-09-27", "-D", "false")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("pack databases: %v\n%s", err, output)
	}
	if _, err := os.Stat(filepath.Join(dir, "DATABASE_NOTICES.txt")); !os.IsNotExist(err) {
		t.Fatalf("packer modified source database directory: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "DATABASE_NOTICES.txt"), []byte("stale"), 0o644); err != nil {
		t.Fatal(err)
	}
	cmd = exec.Command("bash", "../../zeus/scripts/pack-dbs.sh", "-d", dir, "-o", out, "-v", "2026-09-27", "-D", "false")
	if output, err := cmd.CombinedOutput(); err == nil || !bytes.Contains(output, []byte("Database notices differ")) {
		t.Fatalf("packer did not reject stale notices: %v\n%s", err, output)
	}

	f, err := os.Open(filepath.Join(out, "2026-09-27.tar.gz"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	defer zr.Close()
	tr := tar.NewReader(zr)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			t.Fatal("packed archive omitted notices")
		}
		if err != nil {
			t.Fatal(err)
		}
		if h.Name == "dbs/DATABASE_NOTICES.txt" {
			body, err := io.ReadAll(tr)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(body, databaseNotices) {
				t.Fatal("packed archive contains different notices")
			}
			return
		}
	}
}

func TestNightlyDatabaseArchiveIncludesNotices(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "temp-dbs")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "nightly.tar.gz")
	sum, size, err := new(DBServer).createTarball(dir, path)
	if err != nil {
		t.Fatal(err)
	}
	if len(sum) != 64 || size == 0 {
		t.Fatalf("sum %q size %d", sum, size)
	}
	if err := verifySHA256(path, sum); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	defer zr.Close()
	tr := tar.NewReader(zr)
	h, err := tr.Next()
	if err != nil {
		t.Fatal(err)
	}
	if h.Name != "DATABASE_NOTICES.txt" {
		t.Fatalf("nightly archive first entry: %q", h.Name)
	}
	body, err := io.ReadAll(tr)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(body, databaseNotices) {
		t.Fatal("nightly archive contains different notices")
	}
}
