package dbs

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestArchivesExcludeUserInstalledAndRetiredData(t *testing.T) {
	for _, method := range []string{"generator", "server", "packer"} {
		t.Run(method, func(t *testing.T) {
			root := t.TempDir()
			dir := filepath.Join(root, "dbs")
			if err := os.Mkdir(dir, 0o755); err != nil {
				t.Fatal(err)
			}
			for _, name := range []string{"nmap-service-probes", "domain-whitelist.csv", "GeoLite2-ASN.mmdb", "GeoLite2-City.mmdb", "GeoLite2-Country.mmdb", "sample.json"} {
				if err := os.WriteFile(filepath.Join(dir, name), []byte("fixture"), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			var archive bytes.Buffer
			var rejected error
			switch method {
			case "generator":
				rejected = makeTarball(dir, "dbs", &archive)
			case "server":
				path := filepath.Join(root, "release.tar.gz")
				_, _, rejected = new(DBServer).createTarball(dir, path)
			case "packer":
				cmd := exec.Command("bash", "../../zeus/scripts/pack-dbs.sh", "-d", dir, "-o", root, "-D", "false")
				_, rejected = cmd.CombinedOutput()
			}
			if rejected == nil {
				t.Fatal("unapproved ambient datasets were published")
			}
			if _, err := os.Stat(filepath.Join(dir, "nmap-service-probes")); err != nil {
				t.Fatalf("modified user-installed source: %v", err)
			}
		})
	}
}

func TestGeneratedDatabaseArchiveIncludesNotices(t *testing.T) {
	dir, approvals, manifest := reviewedFixture(t)
	t.Setenv("NC_DBS_APPROVALS", approvals)

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
		if h.Name == "DATABASE_NOTICES.txt" {
			body, err := io.ReadAll(tr)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(body, releaseNotices(manifest)) {
				t.Fatal("database archive contains different notices")
			}
			return
		}
	}
}

func TestPackedDatabaseArchiveIncludesNotices(t *testing.T) {
	dir, approvals, manifest := reviewedFixture(t)
	out := t.TempDir()
	meta, err := PackV3(dir, out, approvals)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "DATABASE_NOTICES.txt")); !os.IsNotExist(err) {
		t.Fatalf("packer modified source database directory: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "DATABASE_NOTICES.txt"), []byte("stale"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := PackV3(dir, out, approvals); err == nil || !strings.Contains(err.Error(), "stale database notices") {
		t.Fatalf("stale notice accepted: %v", err)
	}

	f, err := os.Open(filepath.Join(out, meta.Tarball))
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
		if h.Name == "DATABASE_NOTICES.txt" {
			body, err := io.ReadAll(tr)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(body, releaseNotices(manifest)) {
				t.Fatal("packed archive contains different notices")
			}
			return
		}
	}
}

func TestNightlyDatabaseArchiveIncludesNotices(t *testing.T) {
	root := t.TempDir()
	dir, approvals, manifest := reviewedFixture(t)
	t.Setenv("NC_DBS_APPROVALS", approvals)
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
	for {
		h, err := tr.Next()
		if err != nil {
			t.Fatal("missing notices", err)
		}
		if h.Name == "DATABASE_NOTICES.txt" {
			break
		}
	}
	body, err := io.ReadAll(tr)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(body, releaseNotices(manifest)) {
		t.Fatal("nightly archive contains different notices")
	}
}
