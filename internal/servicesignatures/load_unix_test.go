//go:build unix

package servicesignatures

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestLoadRejectsFIFOWithoutBlocking(t *testing.T) {
	if path := os.Getenv("NETCAP_TEST_SIGNATURE_FIFO"); path != "" {
		e, err := Load(path)
		if err == nil || e == nil || e.sourceSHA256 != Builtin().sourceSHA256 {
			t.Fatalf("expected visible built-in fallback: %v", err)
		}
		return
	}
	path := filepath.Join(t.TempDir(), FileName)
	if err := syscall.Mkfifo(path, 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestLoadRejectsFIFOWithoutBlocking$")
	cmd.Env = append(os.Environ(), "NETCAP_TEST_SIGNATURE_FIFO="+path)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("FIFO loader blocked or failed: %v (%v)\n%s", err, ctx.Err(), output)
	}
}
