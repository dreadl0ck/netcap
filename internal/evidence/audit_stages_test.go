package evidence

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func stageFixture(t *testing.T) (*Capture, string) {
	t.Helper()
	directory := t.TempDir()
	capture, err := NewCapture(context.Background(), directory, CaptureConfig{Kind: "live", Source: "fixture"})
	if err != nil {
		t.Fatal(err)
	}
	if err := capture.Close("partial", 1, 0, nil); err != nil {
		t.Fatal(err)
	}
	return capture, directory
}

func TestAuditStageSealsBindRunGenerationAndFileContent(t *testing.T) {
	capture, directory := stageFixture(t)
	name := filepath.Join(directory, "UDP.ncap")
	if err := os.WriteFile(name, []byte("sealed fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := capture.SealAuditStages([]AuditStage{{Type: "UDP", Stage: "packet", State: "sealed", Coverage: "partial", Reason: "input gap", Records: 1, Files: []SealedAuditFile{{Name: "UDP.ncap"}}}}); err != nil {
		t.Fatal(err)
	}
	stage, snapshot, err := ReadAuditStage(directory, capture.RunID(), "UDP", "")
	if err != nil || stage.Records != 1 || stage.Coverage != "partial" || len(stage.Files) != 1 || snapshot.Generation == "" {
		t.Fatal("sealed stage was not readable", stage, snapshot, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := ReadAuditStageContext(ctx, directory, capture.RunID(), "UDP", snapshot.Generation); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled stage verification continued", err)
	}
	for _, arguments := range [][3]string{{"wrong", "UDP", ""}, {capture.RunID(), "UDP", "wrong"}, {capture.RunID(), "TCP", snapshot.Generation}} {
		if _, _, err := ReadAuditStage(directory, arguments[0], arguments[1], arguments[2]); err == nil {
			t.Fatal("invalid stage selection was accepted", arguments)
		}
	}
	if err := os.WriteFile(name, []byte("forged fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ReadAuditStage(directory, capture.RunID(), "UDP", snapshot.Generation); err == nil || !strings.Contains(err.Error(), "sealed audit output changed") || strings.Contains(err.Error(), "size mismatch") {
		t.Fatalf("same-size replacement was not rejected by digest: %v", err)
	}
	if err := os.Truncate(name, stage.Files[0].Size+1); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ReadAuditStage(directory, capture.RunID(), "UDP", snapshot.Generation); err == nil || !strings.Contains(err.Error(), "size mismatch") {
		t.Fatalf("grown sealed output was not rejected at admission: %v", err)
	}
}

func TestAuditStageRejectsLinkedInventory(t *testing.T) {
	capture, directory := stageFixture(t)
	if err := capture.SealAuditStages([]AuditStage{{Type: "UDP", Stage: "packet", State: "sealed", Coverage: "complete"}}); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, AuditStagesFile)
	if err := os.Rename(path, filepath.Join(directory, "original.json")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("original.json", path); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ReadAuditStage(directory, capture.RunID(), "UDP", ""); err == nil {
		t.Fatal("linked audit inventory was admitted")
	}
}

func TestAuditStagesDoNotTurnUnavailableOrNewFilesIntoEmptySuccess(t *testing.T) {
	capture, directory := stageFixture(t)
	if err := capture.SealAuditStages([]AuditStage{{Type: "UDP", Stage: "packet", State: "sealed", Coverage: "partial", Files: []SealedAuditFile{}}, {Type: "HTTP", Stage: "application", State: "failed", Coverage: "partial", Reason: "parser pressure"}}); err != nil {
		t.Fatal(err)
	}
	if stage, _, err := ReadAuditStage(directory, capture.RunID(), "UDP", ""); err != nil || stage.Records != 0 {
		t.Fatal("known empty sealed output unavailable", stage, err)
	}
	if _, _, err := ReadAuditStage(directory, capture.RunID(), "HTTP", ""); err == nil {
		t.Fatal("failed parser became an empty success")
	}
	if err := os.WriteFile(filepath.Join(directory, "UDP.ncap"), []byte("late output"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ReadAuditStage(directory, capture.RunID(), "UDP", ""); err == nil {
		t.Fatal("unsealed new file became readable")
	}
}

func TestAuditStagePublicationFailureBlocksReadiness(t *testing.T) {
	capture, directory := stageFixture(t)
	if err := capture.SealAuditStages([]AuditStage{{Type: "UDP", Stage: "packet", State: "sealed", Coverage: "complete", Records: 1, Files: []SealedAuditFile{{Name: "UDP.ncap"}}}}); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("missing output was not rejected", err)
	}
	if err := capture.MarkAuditOutputReady(); err == nil {
		t.Fatal("failed seal published full readiness")
	}
	if _, err := os.Stat(filepath.Join(directory, AuditStagesFile)); !os.IsNotExist(err) {
		t.Fatal("failed seal published an inventory", err)
	}
}
