//go:build !nomagika && !windows

package file

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	decoderconfig "github.com/dreadl0ck/netcap/internal/decoder/config"
)

func TestSpooledClassifierUsesBoundedInput(t *testing.T) {
	cfg := spoolTestConfig(t)
	dir := decoderconfig.Instance.Out
	binary := filepath.Join(dir, "magika")
	script := `#!/bin/sh
[ "$(/usr/bin/wc -c < "$2")" -eq 524288 ] || exit 3
printf '%s' '[{"result":{"status":"ok","value":{"output":{"label":"text","mime_type":"text/plain","is_text":true},"score":0.99}}}]'
`
	if err := os.WriteFile(binary, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	cfg.FileExtraction.Advanced.EnableMagika = true
	cfg.FileExtraction.SizeLimits.MaxInflightBytes = artifactScanMemory
	cfg.FileExtraction.SizeLimits.MaxScratchBytes = 1 << 20
	SetGlobalConfig(cfg)
	if err := StartAnalysis(dir, "stream-classifier"); err != nil {
		t.Fatal(err)
	}
	defer FinishAnalysis()
	spool, err := SpoolBody(strings.NewReader(strings.Repeat("x", 512<<10)))
	if err != nil {
		t.Fatal(err)
	}
	defer spool.Close()
	content := spool.content
	_, result := analyzeStored(content.file.Name(), content.hashes.SHA256, content.AnalyzerBytes, content)
	if result == nil || result.Label != "text" {
		t.Fatalf("expected classification under a %d-byte buffer budget, got %+v", artifactScanMemory, result)
	}
}
