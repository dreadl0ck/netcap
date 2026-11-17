package file

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	decoderconfig "github.com/dreadl0ck/netcap/internal/decoder/config"
	"github.com/dreadl0ck/netcap/internal/decoder/core"
)

func TestRepeatedArtifactWriteFailuresKeepFirstCauseAndCount(t *testing.T) {
	old := GetGlobalConfig()
	SetGlobalConfig(GetDefaultConfig())
	t.Cleanup(func() { SetGlobalConfig(old) })
	dir := t.TempDir()
	if err := StartAnalysis(dir, "write-failures"); err != nil {
		t.Fatal(err)
	}
	first := errors.New("first write failure")
	RecordArtifactWriteError(first)
	for range 1000 {
		RecordArtifactWriteError(errors.New("later write failure"))
	}
	_, persistenceErr := FinishAnalysis()
	if !errors.Is(persistenceErr, first) || persistenceErr.Error() != first.Error() {
		t.Fatal(persistenceErr)
	}
	data, err := os.ReadFile(filepath.Join(dir, AnalysisReportFile))
	if err != nil {
		t.Fatal(err)
	}
	var report AnalysisReport
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatal(err)
	}
	if report.State != "partial" || report.PersistenceFailures != 1001 || report.Error != first.Error() {
		t.Fatalf("incorrect persistence summary: state=%s count=%d error=%s", report.State, report.PersistenceFailures, report.Error)
	}
}

type blockedAnalyzer struct{ started chan struct{} }

func (b *blockedAnalyzer) Digest() string { return "owned-blocking-analyzer" }
func (b *blockedAnalyzer) ScanBytesContext(ctx context.Context, _ []byte) ([]string, error) {
	select {
	case b.started <- struct{}{}:
	default:
	}
	<-ctx.Done()
	return nil, ctx.Err()
}

func TestAnalysisQueueCancellationAndSaveLock(t *testing.T) {
	old, oldDecoder := GetGlobalConfig(), decoderconfig.Instance
	oldWriter, oldCount := Decoder.Writer, Decoder.NumRecordsWritten
	defer func() {
		SetGlobalConfig(old)
		decoderconfig.Instance = oldDecoder
		Decoder.Writer, Decoder.NumRecordsWritten = oldWriter, oldCount
	}()
	cfg := GetDefaultConfig()
	cfg.FileExtraction.Advanced.UseMagicDetection = false
	SetGlobalConfig(cfg)
	dir := t.TempDir()
	decoderconfig.Instance = &decoderconfig.Config{Out: dir, FileStorage: "files"}
	writer := &savedFileWriter{}
	Decoder.Writer = writer
	if err := StartAnalysis(dir, "pressure"); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if currentAnalysis() != nil {
			CancelAnalysis()
			FinishAnalysis()
		}
	}()
	m := currentAnalysis()
	backend := &blockedAnalyzer{started: make(chan struct{}, 2)}
	m.yara = backend
	var wg sync.WaitGroup
	for i := 0; i < 40; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			body := []byte(fmt.Sprintf("unique-content-%d", n))
			if err := SaveFileEnhanced(&core.ConversationInfo{Ident: fmt.Sprint(n), FirstClientPacket: time.Unix(1, 0)}, "owned", "owned.bin", nil, body, nil, "", "application/octet-stream", 0, "", "client_to_server", "HTTP"); err != nil {
				t.Error(err)
			}
		}(i)
	}
	for range 2 {
		select {
		case <-backend.started:
		case <-time.After(5 * time.Second):
			t.Fatal("slow analyzer held the content-save lock or no second worker")
		}
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		m.mu.Lock()
		rejected := m.report.Rejected
		m.mu.Unlock()
		if rejected > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("queue pressure was not bounded")
		}
		time.Sleep(time.Millisecond)
	}
	CancelAnalysis()
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("cancelled jobs leaked waiters")
	}
	analysisErr, persistErr := FinishAnalysis()
	if analysisErr == nil || persistErr != nil {
		t.Fatalf("incomplete result lost: %v %v", analysisErr, persistErr)
	}
	if len(writer.records) != 40 {
		t.Fatalf("analysis failures lost file occurrences: %d", len(writer.records))
	}
	for _, result := range m.report.Results {
		for _, a := range result.Analyzers {
			if a.State != "cancelled" {
				t.Fatalf("pending/clean state after cancellation: %+v", a)
			}
		}
	}
}
