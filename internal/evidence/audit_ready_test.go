package evidence

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestAuditOutputReadinessRequiresFinalizedCapture(t *testing.T) {
	for _, tc := range []struct {
		name, status string
		captureError error
		ready        bool
	}{
		{name: "successful", status: "done", ready: true},
		{name: "stopped", status: "stopped", ready: true},
		{name: "partial", status: "partial", ready: true},
		{name: "failure", status: "done", captureError: errors.New("capture failed")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			capture, err := NewCapture(context.Background(), dir, CaptureConfig{Kind: "live", Source: "fixture"})
			if err != nil {
				t.Fatal(err)
			}
			if err := capture.MarkAuditOutputReady(); err == nil {
				t.Fatal("running capture marked ready")
			}
			if _, err := os.Stat(filepath.Join(dir, AuditReadyFile)); !os.IsNotExist(err) {
				t.Fatal("running capture published a marker")
			}
			if err := capture.Close(tc.status, 0, 0, tc.captureError); err != nil {
				t.Fatal(err)
			}
			err = capture.MarkAuditOutputReady()
			if !tc.ready {
				if err == nil {
					t.Fatal("failed capture marked ready")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			data, err := os.ReadFile(filepath.Join(dir, AuditReadyFile))
			if err != nil {
				t.Fatal(err)
			}
			var marker struct {
				Version int    `json:"version"`
				RunID   string `json:"runId"`
			}
			if err := json.Unmarshal(data, &marker); err != nil || marker.Version != 1 || marker.RunID != capture.manifest.RunID {
				t.Fatalf("marker does not identify finalized capture: %s %v", data, err)
			}
			info, err := os.Stat(filepath.Join(dir, AuditReadyFile))
			if err != nil || info.Mode().Perm() != 0600 {
				t.Fatalf("marker permissions: %v %v", info, err)
			}
			if err := capture.MarkAuditOutputReady(); err == nil {
				t.Fatal("duplicate publication overwrote readiness")
			}
		})
	}
}

func TestAuditOutputReadyRefusesExistingSymlink(t *testing.T) {
	dir := t.TempDir()
	capture, err := NewCapture(context.Background(), dir, CaptureConfig{Kind: "live", Source: "fixture"})
	if err != nil {
		t.Fatal(err)
	}
	if err := capture.Close("done", 0, 0, nil); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "sentinel")
	if err := os.WriteFile(target, []byte("unchanged"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(dir, AuditReadyFile)); err != nil {
		t.Fatal(err)
	}
	if err := capture.MarkAuditOutputReady(); err == nil {
		t.Fatal("accepted symlink marker")
	}
	data, err := os.ReadFile(target)
	if err != nil || string(data) != "unchanged" {
		t.Fatalf("changed sentinel: %q %v", data, err)
	}
}
