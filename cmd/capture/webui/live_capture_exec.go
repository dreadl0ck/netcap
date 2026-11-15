//go:build !appstore

package webui

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

func liveCaptureFailure(err error, out string) string {
	return summariseAnalysisFailure(err, filepath.Join(out, "live-capture.log"))
}

func (s *Server) startLiveHelper(ctx context.Context, args []string, out string) (func() error, error) {
	path := resolveHelperExecutable()
	if path == "" {
		return nil, fmt.Errorf("capture helper is unavailable")
	}
	log, err := os.OpenFile(filepath.Join(out, "live-capture.log"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return nil, err
	}
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Env = helperEnvironment()
	cmd.Stdout = log
	cmd.Stderr = log
	cmd.Cancel = func() error { return cmd.Process.Signal(os.Interrupt) }
	cmd.WaitDelay = 5 * time.Second
	s.currentCmdMutex.Lock()
	s.mu.RLock()
	stopping := s.processingStopping
	s.mu.RUnlock()
	if stopping {
		s.currentCmdMutex.Unlock()
		log.Close()
		return nil, fmt.Errorf("capture server is stopping")
	}
	if err := cmd.Start(); err != nil {
		s.currentCmdMutex.Unlock()
		log.Close()
		return nil, err
	}
	s.currentProc = cmd.Process
	s.currentCmdMutex.Unlock()
	return func() error {
		defer log.Close()
		err := cmd.Wait()
		s.currentCmdMutex.Lock()
		if s.currentProc == cmd.Process {
			s.currentProc = nil
		}
		s.currentCmdMutex.Unlock()
		if ctx.Err() != nil && cmd.ProcessState != nil && cmd.ProcessState.Success() {
			return nil
		}
		return err
	}, nil
}
