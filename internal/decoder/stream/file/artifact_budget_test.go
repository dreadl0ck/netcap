package file

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestArtifactConfigDefaultsAndFreeze(t *testing.T) {
	old := GetGlobalConfig()
	defer SetGlobalConfig(old)
	path := filepath.Join(t.TempDir(), "file.yml")
	if err := os.WriteFile(path, []byte("file_extraction:\n  advanced:\n    compute_entropy: false\n"), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.FileExtraction.Advanced.ComputeEntropy || !cfg.FileExtraction.Enabled || cfg.FileExtraction.SizeLimits.MaxFileSize != 100<<20 {
		t.Fatal("omitted defaults or false lost")
	}
	SetGlobalConfig(cfg)
	if err := StartAnalysis(t.TempDir(), "fixture"); err != nil {
		t.Fatal(err)
	}
	cfg.FileExtraction.SizeLimits.MaxFileSize = 10
	SetGlobalConfig(cfg)
	mutated := GetGlobalConfig()
	mutated.FileExtraction.SizeLimits.MaxFileSize = 1
	if GetMaxFileSize() != 100<<20 {
		t.Fatal("active run policy mutated")
	}
	if _, err := FinishAnalysis(); err != nil {
		t.Fatal(err)
	}
	if GetMaxFileSize() != 10 {
		t.Fatal("pending configuration did not take effect")
	}
	if err := os.WriteFile(path, []byte("file_extraction:\n  size_limits:\n    max_file_size: -1\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(path); err == nil {
		t.Fatal("negative limit admitted")
	}
}

func TestArtifactBudgetReservations(t *testing.T) {
	cfg := GetDefaultConfig()
	cfg.FileExtraction.SizeLimits.MaxFileSize = 100
	cfg.FileExtraction.SizeLimits.MaxInflightBytes = 200
	old := GetGlobalConfig()
	SetGlobalConfig(cfg)
	defer SetGlobalConfig(old)
	if err := StartAnalysis(t.TempDir(), "fixture"); err != nil {
		t.Fatal(err)
	}
	b, release, err := ReadBody(bytes.NewReader(bytes.Repeat([]byte("x"), 100)))
	if err != nil || len(b) != 100 {
		t.Fatalf("exact limit: %d %v", len(b), err)
	}
	_, release2, err := ReadBody(bytes.NewReader(bytes.Repeat([]byte("y"), 101)))
	if !errors.Is(err, ErrArtifactLimit) {
		t.Fatalf("expansion not refused: %v", err)
	}
	_, release3, err := ReadBody(bytes.NewReader([]byte("z")))
	release3()
	if err == nil {
		t.Fatal("inflight allocation budget ignored")
	}
	release2()
	release()
	release()
	b, r, err := ReadBody(bytes.NewReader([]byte("valid")))
	r()
	if err != nil || string(b) != "valid" {
		t.Fatal("reservation not released")
	}
	if _, err := FinishAnalysis(); err != nil {
		t.Fatal(err)
	}
}
