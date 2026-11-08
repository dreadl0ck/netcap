package netio

import (
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"testing"
)

func TestReaderReleasesReadOnlyFile(t *testing.T) {
	for _, suffix := range []string{".ncap", ".ncap.gz"} {
		t.Run(suffix, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "audit"+suffix)
			data := []byte("fixture")
			if suffix == ".ncap.gz" {
				var b bytes.Buffer
				w := gzip.NewWriter(&b)
				if _, err := w.Write(data); err != nil {
					t.Fatal(err)
				}
				if err := w.Close(); err != nil {
					t.Fatal(err)
				}
				data = b.Bytes()
			}
			if err := os.WriteFile(path, data, 0600); err != nil {
				t.Fatal(err)
			}
			r, err := Open(path, 1024)
			if err != nil {
				t.Fatal(err)
			}
			if err := r.Close(); err != nil {
				t.Fatal(err)
			}
			if fd := r.file.Fd(); fd != ^uintptr(0) {
				t.Fatalf("descriptor still open: %d", fd)
			}
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestReaderInvalidGzipReleasesFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "invalid.ncap.gz")
	if err := os.WriteFile(path, []byte("not a gzip stream"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path, 1024); err == nil {
		t.Fatal("invalid gzip accepted")
	}
	// Windows refuses removal while the failed constructor retains the descriptor.
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
}
