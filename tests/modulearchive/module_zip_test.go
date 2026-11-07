package modulearchive

import (
	"archive/tar"
	"bytes"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/mod/module"
	"golang.org/x/mod/zip"
)

type sourceFile struct {
	name string
	info os.FileInfo
	data []byte
}

func (f sourceFile) Path() string                 { return f.name }
func (f sourceFile) Lstat() (os.FileInfo, error)  { return f.info, nil }
func (f sourceFile) Open() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(f.data)), nil }

func TestTrackedSourceIsConsumableAsGoModule(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	command := func(args ...string) []byte {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-c", "safe.directory=" + root}, args...)...)
		cmd.Dir = root
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("git %v: %v", args, err)
		}
		return out
	}
	tree := strings.TrimSpace(string(command("write-tree")))
	archive := tar.NewReader(bytes.NewReader(command("archive", tree)))
	var files []zip.File
	for {
		header, err := archive.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if !header.FileInfo().Mode().IsRegular() {
			continue
		}
		data, err := io.ReadAll(archive)
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, sourceFile{header.Name, header.FileInfo(), data})
	}
	checked, err := zip.CheckFiles(files)
	if err != nil {
		t.Fatal(err)
	}
	if err := checked.Err(); err != nil {
		t.Fatal(err)
	}
	if len(checked.Valid) < 100 {
		t.Fatalf("unexpectedly empty source inventory: %d", len(checked.Valid))
	}
	version := module.Version{Path: "github.com/dreadl0ck/netcap", Version: "v0.15.4"}
	path := filepath.Join(t.TempDir(), "module.zip")
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	err = zip.Create(file, version, files)
	closeErr := file.Close()
	if err != nil {
		t.Fatal(err)
	}
	if closeErr != nil {
		t.Fatal(closeErr)
	}
	if _, err = zip.CheckZip(version, path); err != nil {
		t.Fatal(err)
	}
}
