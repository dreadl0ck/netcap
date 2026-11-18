package file

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"testing"
)

type panicBodyReader struct{}

func (panicBodyReader) Read([]byte) (int, error) { panic("fixture read failure") }

func TestBodyReaderPanicReturnsAllocationCredits(t *testing.T) {
	cfg, old := GetDefaultConfig(), GetGlobalConfig()
	cfg.FileExtraction.SizeLimits.MaxFileSize = 1024
	cfg.FileExtraction.SizeLimits.MaxInflightBytes = 2048
	SetGlobalConfig(cfg)
	t.Cleanup(func() { SetGlobalConfig(old) })
	if err := StartAnalysis(t.TempDir(), "body-panic"); err != nil {
		t.Fatal(err)
	}
	defer FinishAnalysis()
	for range 5 {
		func() {
			defer func() {
				if recover() != "fixture read failure" {
					t.Error("expected original panic")
				}
			}()
			_, release, _ := ReadBody(panicBodyReader{})
			release()
		}()
	}
	if err := reserveBuffer(2048); err != nil {
		t.Fatal("panic leaked budget", err)
	}
	releaseBuffer(2048)
}

func TestSmallBodiesDoNotConsumeLargeAllocationReservations(t *testing.T) {
	cfg, old := GetDefaultConfig(), GetGlobalConfig()
	cfg.FileExtraction.SizeLimits.MaxFileSize = 1024
	cfg.FileExtraction.SizeLimits.MaxInflightBytes = 2048
	SetGlobalConfig(cfg)
	t.Cleanup(func() { SetGlobalConfig(old) })
	if err := StartAnalysis(t.TempDir(), "small-body"); err != nil {
		t.Fatal(err)
	}
	defer FinishAnalysis()
	var releases []func()
	defer func() {
		for _, release := range releases {
			release()
		}
	}()
	for _, r := range []io.Reader{http.NoBody, bytes.NewReader([]byte("small")), bytes.NewReader([]byte("small")), bytes.NewReader([]byte("small"))} {
		body, release, err := ReadBody(r)
		releases = append(releases, release)
		if err != nil || len(body) > 5 {
			t.Fatal("small body exceeded in-flight budget", len(body), err)
		}
	}
}

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

func TestReadBodyExactFitAtSharedBudget(t *testing.T) {
	cfg := GetDefaultConfig()
	cfg.FileExtraction.SizeLimits.MaxFileSize = 4096
	cfg.FileExtraction.SizeLimits.MaxInflightBytes = 512
	old := GetGlobalConfig()
	SetGlobalConfig(cfg)
	defer SetGlobalConfig(old)
	if err := StartAnalysis(t.TempDir(), "fixture"); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if _, err := FinishAnalysis(); err != nil {
			t.Error(err)
		}
	}()
	want := bytes.Repeat([]byte("x"), 512)
	for _, extra := range []bool{false, true} {
		input := bytes.Clone(want)
		if extra {
			input = append(input, 'y')
		}
		body, release, err := ReadBody(bytes.NewReader(input))
		release()
		if !bytes.Equal(body, want) || (!extra && err != nil) || (extra && !errors.Is(err, errSharedArtifactBudget)) {
			t.Fatalf("extra=%t: len=%d err=%v", extra, len(body), err)
		}
	}
}
