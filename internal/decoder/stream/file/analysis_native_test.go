//go:build !noyara

package file

import (
	"bytes"
	"encoding/json"
	decoderconfig "github.com/dreadl0ck/netcap/internal/decoder/config"
	"github.com/dreadl0ck/netcap/internal/decoder/core"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

const analysisRule = `rule owned_fixture { strings: $a="NETCAP_BATCH2_MARKER" condition: $a }`

func TestAnalyzerSnapshotAndEnabledRules(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "fixture.yar")
	if err := os.WriteFile(path, []byte(analysisRule), 0600); err != nil {
		t.Fatal(err)
	}
	scanner, err := NewYaraScanner(dir)
	if err != nil {
		t.Fatal(err)
	}
	digest := scanner.Digest()
	if matches, err := scanner.ScanBytes([]byte("NETCAP_BATCH2_MARKER")); err != nil || len(matches) != 1 {
		t.Fatalf("known hit: %v %v", matches, err)
	}
	if matches, err := scanner.ScanBytes([]byte("benign control")); err != nil || len(matches) != 0 {
		t.Fatalf("clean control: %v %v", matches, err)
	}
	if err := os.WriteFile(path, []byte("not a YARA rule"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := scanner.Reload(); err == nil {
		t.Fatal("invalid snapshot activated")
	}
	if scanner.Digest() != digest {
		t.Fatal("failed reload replaced digest")
	}
	if matches, err := scanner.ScanBytes([]byte("NETCAP_BATCH2_MARKER")); err != nil || len(matches) != 1 {
		t.Fatal("last good snapshot lost")
	}
	if err := os.WriteFile(filepath.Join(dir, "yara-rules-meta.json"), []byte(`{"fixture.yar":false}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := scanner.Reload(); err != nil {
		t.Fatal(err)
	}
	if scanner.RuleCount() != 0 {
		t.Fatal("disabled rule compiled")
	}
	if _, err := scanner.ScanBytes([]byte("NETCAP_BATCH2_MARKER")); err == nil {
		t.Fatal("zero rules reported as clean no-match")
	}
}

func TestAnalyzerDedupKeepsFileOccurrences(t *testing.T) {
	oldCfg, oldDecoder := GetGlobalConfig(), decoderconfig.Instance
	oldWriter, oldCount := Decoder.Writer, Decoder.NumRecordsWritten
	defer func() {
		SetGlobalConfig(oldCfg)
		decoderconfig.Instance = oldDecoder
		Decoder.Writer, Decoder.NumRecordsWritten = oldWriter, oldCount
	}()
	dir, rulesDir := t.TempDir(), t.TempDir()
	if err := os.WriteFile(filepath.Join(rulesDir, "fixture.yar"), []byte(analysisRule), 0600); err != nil {
		t.Fatal(err)
	}
	cfg := GetDefaultConfig()
	cfg.FileExtraction.Advanced.EnableYaraScanning = true
	cfg.FileExtraction.Advanced.YaraRulesPath = rulesDir
	cfg.FileExtraction.Advanced.UseMagicDetection = false
	SetGlobalConfig(cfg)
	decoderconfig.Instance = &decoderconfig.Config{Out: dir, FileStorage: "files"}
	w := &savedFileWriter{}
	Decoder.Writer = w
	if err := StartAnalysis(dir, "fixture-run"); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if currentAnalysis() != nil {
			FinishAnalysis()
		}
	}()
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			conv := &core.ConversationInfo{Ident: "fixture", CommunityID: "1:fixture", FirstClientPacket: time.Unix(1, 0)}
			if err := SaveFileEnhanced(conv, "owned", "owned.bin", nil, []byte("NETCAP_BATCH2_MARKER"), nil, "", "application/octet-stream", 0, "", "client_to_server", "HTTP"); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if a, p := FinishAnalysis(); a != nil || p != nil {
		t.Fatalf("finish: %v %v", a, p)
	}
	if len(w.records) != 20 {
		t.Fatalf("lost occurrences: %d", len(w.records))
	}
	paths := map[string]bool{}
	for _, record := range w.records {
		paths[record.Location] = true
		if len(record.YaraMatches) != 1 {
			t.Fatal("known YARA hit missing from emitted file")
		}
		b, err := os.ReadFile(record.Location)
		if err != nil || !bytes.Equal(b, []byte("NETCAP_BATCH2_MARKER")) {
			t.Fatal("stored bytes changed")
		}
	}
	if len(paths) != 1 {
		t.Fatal("content deduplication lost")
	}
	b, err := os.ReadFile(filepath.Join(dir, AnalysisReportFile))
	if err != nil {
		t.Fatal(err)
	}
	var report AnalysisReport
	if err := json.Unmarshal(b, &report); err != nil {
		t.Fatal(err)
	}
	if report.State != "complete" || report.RunID != "fixture-run" || len(report.Results) != 1 || report.ExecutedJobs != 1 || report.CacheHits != 19 {
		t.Fatalf("report: %+v", report)
	}
}

func TestRequestedAnalyzerAdmissionAndResultFailure(t *testing.T) {
	old := GetGlobalConfig()
	defer SetGlobalConfig(old)
	cfg := GetDefaultConfig()
	cfg.FileExtraction.Advanced.EnableYaraScanning = true
	cfg.FileExtraction.Advanced.YaraRulesPath = filepath.Join(t.TempDir(), "missing")
	SetGlobalConfig(cfg)
	if err := StartAnalysis(t.TempDir(), "fixture"); err == nil {
		t.Fatal("missing rules silently admitted")
	}
	SetGlobalConfig(GetDefaultConfig())
	dir := t.TempDir()
	if err := StartAnalysis(dir, "fixture"); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dir, AnalysisReportFile)); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, AnalysisReportFile), 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := FinishAnalysis(); err == nil {
		t.Fatal("result persistence failed silently")
	}
}
