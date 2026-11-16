//go:build unix

package mcp

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestCaptureUploadRejectsSpecialFiles(t *testing.T) {
	dir := t.TempDir()
	fifo := filepath.Join(dir, "fifo.pcap")
	if err := unix.Mkfifo(fifo, 0600); err != nil {
		t.Fatal(err)
	}
	device := filepath.Join(dir, "device.pcap")
	if err := os.Symlink("/dev/zero", device); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{fifo, device} {
		if f, _, err := openCaptureUpload(path, maxCaptureUpload); err == nil {
			f.Close()
			t.Errorf("accepted %s", path)
		}
	}
	// Exercise the nonblocking opener independently of the preliminary stat.
	f, err := openCaptureNonblocking(fifo)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
}
