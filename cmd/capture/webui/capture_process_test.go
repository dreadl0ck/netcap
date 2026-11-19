//go:build !appstore

package webui

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"testing"
	"time"
)

func TestCaptureProcessShutdownOwnsRunningHelper(t *testing.T) {
	if os.Getenv("NETCAP_TEST_CAPTURE_PROCESS_CHILD") == "1" {
		time.Sleep(30 * time.Second)
		return
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	child := func() *exec.Cmd {
		cmd := exec.CommandContext(ctx, executable, "-test.run=^TestCaptureProcessShutdownOwnsRunningHelper$")
		cmd.Env = append(os.Environ(), "NETCAP_TEST_CAPTURE_PROCESS_CHILD=1")
		return cmd
	}
	s := &Server{shutdownChan: make(chan struct{})}
	first := child()
	if err := s.startCaptureProcess(first); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		err := first.Wait()
		s.releaseCaptureProcess(first.Process)
		done <- err
	}()
	defer first.Process.Kill()
	second := child()
	if err := s.startCaptureProcess(second); err == nil {
		_ = second.Process.Kill()
		_ = second.Wait()
		t.Fatal("started a second capture helper while the first owned the slot")
	}
	if err := s.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err == nil || ctx.Err() != nil {
			t.Fatalf("shutdown did not terminate the helper: wait=%v context=%v", err, ctx.Err())
		}
	case <-ctx.Done():
		t.Fatal("helper remained running after shutdown")
	}
	if err := s.startCaptureProcess(child()); !errors.Is(err, errAnalysisStopping) {
		t.Fatalf("unexpected post-shutdown admission: %v", err)
	}
}
