//go:build !nomagika && !windows

package file

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	decoderconfig "github.com/dreadl0ck/netcap/internal/decoder/config"
)

func TestSpooledClassifierUsesBoundedInput(t *testing.T) {
	testSpooledClassifier(t, false)
}

func TestSpooledClassifierSurvivesYaraBufferLimit(t *testing.T) {
	if !YaraAvailable() {
		t.Skip("native YARA unavailable")
	}
	testSpooledClassifier(t, true)
}

func testSpooledClassifier(t *testing.T, yara bool) {
	t.Helper()
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
	if yara {
		rules := t.TempDir()
		if err := os.WriteFile(filepath.Join(rules, "fixture.yar"), []byte(`rule fixture { condition: true }`), 0600); err != nil {
			t.Fatal(err)
		}
		cfg.FileExtraction.Advanced.EnableYaraScanning = true
		cfg.FileExtraction.Advanced.YaraRulesPath = rules
	}
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
	if yara {
		data, err := os.ReadFile(filepath.Join(dir, AnalysisReportFile))
		if err != nil {
			t.Fatal(err)
		}
		var report AnalysisReport
		if err := json.Unmarshal(data, &report); err != nil {
			t.Fatal(err)
		}
		row := report.Results[content.hashes.SHA256]
		if row == nil || len(row.Analyzers) != 2 || row.Analyzers[0].Engine != "yara-x" || row.Analyzers[0].State != "failed" || !strings.Contains(row.Analyzers[0].Error, ErrArtifactLimit.Error()) || row.Analyzers[1].Outcome != "classified" {
			t.Fatalf("analyzer outcomes not isolated: %+v", row)
		}
	}
}
