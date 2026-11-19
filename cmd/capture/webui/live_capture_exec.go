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
	path, prefix := captureHelperCommand()
	if path == "" {
		return nil, fmt.Errorf("capture helper is unavailable")
	}
	log, err := os.OpenFile(filepath.Join(out, "live-capture.log"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return nil, err
	}
	cmd := exec.CommandContext(ctx, path, append(prefix, args...)...)
	cmd.Env = helperEnvironment()
	cmd.Stdout = log
	cmd.Stderr = log
	cmd.Cancel = func() error { return cmd.Process.Signal(os.Interrupt) }
	cmd.WaitDelay = 5 * time.Second
	if err := s.startCaptureProcess(cmd); err != nil {
		log.Close()
		return nil, err
	}
	return func() error {
		defer log.Close()
		err := cmd.Wait()
		s.releaseCaptureProcess(cmd.Process)
		if ctx.Err() != nil && cmd.ProcessState != nil && cmd.ProcessState.Success() {
			return nil
		}
		return err
	}, nil
}

func (s *Server) startCaptureProcess(cmd *exec.Cmd) error {
	s.currentCmdMutex.Lock()
	defer s.currentCmdMutex.Unlock()
	s.mu.RLock()
	stopping := s.processingStopping
	s.mu.RUnlock()
	if stopping {
		return errAnalysisStopping
	}
	if s.currentProc != nil {
		return fmt.Errorf("capture helper is already running")
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	s.currentProc = cmd.Process
	return nil
}

func (s *Server) releaseCaptureProcess(process *os.Process) {
	s.currentCmdMutex.Lock()
	defer s.currentCmdMutex.Unlock()
	if s.currentProc == process {
		s.currentProc = nil
	}
}
