//go:build !appstore

package webui

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestAuxiliaryCaptureOutputRequiresAdmittedDigest(t *testing.T) {
	job := &AnalysisJob{OutputDir: t.TempDir(), reproductionSource: reproductionSource{SHA256: strings.Repeat("a", 64)}}
	for _, tc := range []struct {
		name, digest string
		valid        bool
	}{
		{"absent digest", "", false},
		{"different input", strings.Repeat("b", 64), false},
		{"admitted input", job.reproductionSource.SHA256, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data := []byte(`{"inputSHA256":"` + tc.digest + `"}`)
			if err := os.WriteFile(filepath.Join(job.OutputDir, "capture-manifest.json"), data, 0600); err != nil {
				t.Fatal(err)
			}
			if err := verifyAuxiliaryCaptureOutput(t.Context(), job); (err == nil) != tc.valid {
				t.Fatalf("verification error = %v, want success = %t", err, tc.valid)
			}
		})
	}
}

func TestAuxiliaryHelperDeadlineRecordsFailure(t *testing.T) {
	t.Setenv("NETCAP_TEST_CAPTURE_PROCESS_CHILD", "1")
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	input := filepath.Join(dir, "capture.pcap")
	if err := os.WriteFile(input, []byte("fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	s := &Server{fileErrors: make(map[string]FileError)}
	job := &AnalysisJob{InputFile: input, OutputDir: dir, captureLane: captureAuxiliary,
		deferCompletion: true, reproductionSource: snapshotReproductionSource(input, nil, nil)}
	s.runOfflineCaptureHelper(job, executable, []string{"-test.run=^TestCaptureProcessShutdownOwnsRunningHelper$", "--"}, 250*time.Millisecond)
	failure, ok := s.GetFileError(input)
	if !ok || !strings.Contains(failure.Error, "exceeded its 250ms execution limit") || job.postCapture != nil {
		t.Fatalf("deadline did not fail the job before completion: failure=%+v", failure)
	}
	if s.captureProcesses[captureAuxiliary] != nil {
		t.Fatal("timed-out process retained its slot")
	}
}

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
	start := func(lane captureProcessLane) <-chan error {
		cmd := child()
		if err := s.startCaptureProcess(cmd, lane); err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() {
			err := cmd.Wait()
			s.releaseCaptureProcess(cmd.Process, lane)
			done <- err
		}()
		t.Cleanup(func() { _ = cmd.Process.Kill() })
		return done
	}
	regular, auxiliary := start(captureOffline), start(captureAuxiliary)
	for _, lane := range []captureProcessLane{captureOffline, captureAuxiliary, captureLive} {
		cmd := child()
		if err := s.startCaptureProcess(cmd, lane); err == nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
			t.Fatalf("admitted competing helper in lane %d", lane)
		}
	}
	if err := s.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	for _, done := range []<-chan error{regular, auxiliary} {
		select {
		case err := <-done:
			if err == nil || ctx.Err() != nil {
				t.Fatalf("shutdown did not terminate the helper: wait=%v context=%v", err, ctx.Err())
			}
		case <-ctx.Done():
			t.Fatal("helper remained running after shutdown")
		}
	}
	if err := s.startCaptureProcess(child(), captureAuxiliary); !errors.Is(err, errAnalysisStopping) {
		t.Fatalf("unexpected post-shutdown admission: %v", err)
	}
}
