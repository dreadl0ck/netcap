package capture

import (
	"errors"
	"fmt"
	"io"
	"os"
	"runtime/pprof"
	"sync"
)

// Prevent a second command from truncating the current command's profile.
var cpuProfileMu sync.Mutex

// profileWriter retains errors that runtime/pprof does not return to its caller.
type profileWriter struct {
	io.WriteCloser
	err error
}

func (w *profileWriter) Write(p []byte) (int, error) {
	n, err := w.WriteCloser.Write(p)
	if n < len(p) && err == nil {
		err = io.ErrShortWrite
	}
	w.err = errors.Join(w.err, err)
	return n, err
}

// Profiles cover command returns and the collector's first handled SIGINT/SIGTERM.
// Second signals, SIGKILL, analyzer/HTTP shutdown exits and legacy library Fatals
// bypass finalization; their output must not be treated as a complete profile.
func startCPUProfile(path string) (func() error, error) {
	if !cpuProfileMu.TryLock() {
		return nil, errors.New("CPU profiling already owned by another capture")
	}
	f, err := os.Create(path)
	if err != nil {
		cpuProfileMu.Unlock()
		return nil, fmt.Errorf("create CPU profile: %w", err)
	}
	return acquireCPUProfile(f)
}

// acquireCPUProfile takes the locked command ownership and closes w on failure.
func acquireCPUProfile(w io.WriteCloser) (func() error, error) {
	writer := &profileWriter{WriteCloser: w}
	if err := pprof.StartCPUProfile(writer); err != nil {
		closeErr := w.Close()
		cpuProfileMu.Unlock()
		return nil, errors.Join(fmt.Errorf("start CPU profile: %w", err), closeErr)
	}
	return sync.OnceValue(func() error {
		defer cpuProfileMu.Unlock()
		// Stop joins the runtime writer before reading its retained error.
		pprof.StopCPUProfile()
		if err := errors.Join(writer.err, w.Close()); err != nil {
			return fmt.Errorf("finalize CPU profile: %w", err)
		}
		return nil
	}), nil
}
