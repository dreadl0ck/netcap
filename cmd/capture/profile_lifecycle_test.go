package capture

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime/pprof"
	"sync"
	"sync/atomic"
	"testing"
)

type failingProfile struct {
	closes             atomic.Int32
	writeErr, closeErr error
}

func (w *failingProfile) Write([]byte) (int, error) { return 0, w.writeErr }
func (w *failingProfile) Close() error              { w.closes.Add(1); return w.closeErr }

func TestCPUProfileConcurrentStopErrors(t *testing.T) {
	writeErr, closeErr := errors.New("profile write failed"), errors.New("profile close failed")
	for _, tc := range []struct {
		name                string
		writeErr, errorWant error
	}{
		{"write error", writeErr, writeErr}, {"short write", nil, io.ErrShortWrite},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := &failingProfile{writeErr: tc.writeErr, closeErr: closeErr}
			cpuProfileMu.Lock()
			stop, err := acquireCPUProfile(w)
			if err != nil {
				t.Fatal(err)
			}
			var wg sync.WaitGroup
			for range 20 {
				wg.Go(func() {
					err := stop()
					if !errors.Is(err, tc.errorWant) || !errors.Is(err, closeErr) {
						t.Errorf("stop = %v", err)
					}
				})
			}
			wg.Wait()
			if w.closes.Load() != 1 {
				t.Fatalf("closed %d times", w.closes.Load())
			}
		})
	}
}

func TestCPUProfileCollision(t *testing.T) {
	var external bytes.Buffer
	if err := pprof.StartCPUProfile(&external); err != nil {
		t.Fatal(err)
	}
	defer pprof.StopCPUProfile()
	w := &failingProfile{}
	cpuProfileMu.Lock()
	if stop, err := acquireCPUProfile(w); err == nil || stop != nil {
		t.Fatal("collision acquired ownership")
	}
	if w.closes.Load() != 1 {
		t.Fatal("collision writer not closed")
	}
	if err := pprof.StartCPUProfile(io.Discard); err == nil {
		pprof.StopCPUProfile()
		t.Fatal("failed acquisition stopped external owner")
	}
}

func TestCPUProfileCommandCollisionPreservesFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cpu.profile")
	stop, err := startCPUProfile(path)
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	if err := os.WriteFile(path, []byte("sentinel"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := startCPUProfile(path); err == nil {
		t.Fatal("second owner accepted")
	}
	b, err := os.ReadFile(path)
	if err != nil || string(b) != "sentinel" {
		t.Fatalf("collision truncated file: %q, %v", b, err)
	}
}

func TestCPUProfileOpenFailureReleasesOwnership(t *testing.T) {
	dir := t.TempDir()
	if _, err := startCPUProfile(dir); err == nil {
		t.Fatal("opened directory as profile")
	}
	stop, err := startCPUProfile(filepath.Join(dir, "cpu.profile"))
	if err != nil {
		t.Fatal(err)
	}
	if err := stop(); err != nil {
		t.Fatal(err)
	}
	if err := stop(); err != nil {
		t.Fatal(err)
	}
}
