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

func TestRejectedAnalysisStartPreservesActiveReport(t *testing.T) {
	old := GetGlobalConfig()
	SetGlobalConfig(GetDefaultConfig())
	t.Cleanup(func() { SetGlobalConfig(old) })
	dir := t.TempDir()
	if err := StartAnalysis(dir, "active"); err != nil {
		t.Fatal(err)
	}
	defer FinishAnalysis()
	if err := StartAnalysis(dir, "rejected"); err == nil {
		t.Fatal("accepted overlapping artifact analysis")
	}
	data, err := os.ReadFile(filepath.Join(dir, AnalysisReportFile))
	if err != nil {
		t.Fatal(err)
	}
	var report AnalysisReport
	if err := json.Unmarshal(data, &report); err != nil || report.RunID != "active" || report.State != "running" {
		t.Fatalf("rejected start replaced active report: %s (%v)", data, err)
	}
}

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
	RecordExtractionIssue(errors.New("scratch budget exceeded"))
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
	if len(report.ExtractionIssues) != 2 || report.ExtractionIssues[0] != "artifact output write failed" || report.ExtractionIssues[1] != "scratch budget exceeded" {
		t.Fatalf("repeated write failures obscured another extraction issue: %v", report.ExtractionIssues)
	}
}

type blockedAnalyzer struct{ started chan struct{} }

type fixtureAnalyzer struct{}

func (fixtureAnalyzer) Digest() string { return "fixture" }

func (fixtureAnalyzer) ScanBytesContext(context.Context, []byte) ([]string, error) {
	return []string{"fixture-match"}, nil
}

func TestAnalyzerIntegrityFailureTakesPrecedenceOverBufferPressure(t *testing.T) {
	old := GetGlobalConfig()
	SetGlobalConfig(GetDefaultConfig())
	t.Cleanup(func() { SetGlobalConfig(old) })
	dir := t.TempDir()
	if err := StartAnalysis(dir, "mixed-analyzer-failure"); err != nil {
		t.Fatal(err)
	}
	defer FinishAnalysis()
	currentAnalysis().yara = fixtureAnalyzer{}
	path := filepath.Join(dir, "fixture.bin")
	if err := os.WriteFile(path, []byte("fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	pressureDigest := ComputeHashes([]byte("pressure")).SHA256
	integrityDigest := ComputeHashes([]byte("original")).SHA256
	analyzeStored(path, pressureDigest, func() ([]byte, func(), error) {
		return nil, nil, errSharedArtifactBudget
	}, nil)
	analyzeStored(path, integrityDigest, func() ([]byte, func(), error) {
		return []byte("modified"), func() {}, nil
	}, nil)
	analysisErr, persistenceErr := FinishAnalysis()
	var partial interface{ ExitCode() int }
	if analysisErr == nil || errors.As(analysisErr, &partial) || persistenceErr != nil {
		t.Fatalf("mixed failures: analysis=%v, persistence=%v", analysisErr, persistenceErr)
	}
	data, err := os.ReadFile(filepath.Join(dir, AnalysisReportFile))
	if err != nil {
		t.Fatal(err)
	}
	var report AnalysisReport
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatal(err)
	}
	if report.State != "partial" || report.ExecutedJobs != 2 {
		t.Fatalf("unexpected outcome: state=%s jobs=%d", report.State, report.ExecutedJobs)
	}
	for digest, want := range map[string]string{pressureDigest: errSharedArtifactBudget.Error(), integrityDigest: "artifact hash changed"} {
		row := report.Results[digest]
		if row == nil || len(row.Analyzers) != 1 || row.Analyzers[0].State != "failed" || row.Analyzers[0].Error != want {
			t.Fatalf("artifact %s: got %+v, want failure %q", digest, row, want)
		}
	}
}

func TestAnalysisShutdownDrainsAcceptedJobsAndRejectsLateWork(t *testing.T) {
	old := GetGlobalConfig()
	SetGlobalConfig(GetDefaultConfig())
	t.Cleanup(func() { SetGlobalConfig(old) })
	dir := t.TempDir()
	if err := StartAnalysis(dir, "shutdown-admission"); err != nil {
		t.Fatal(err)
	}
	defer FinishAnalysis()
	m := currentAnalysis()
	m.yara = fixtureAnalyzer{}
	body := []byte("artifact fixture")
	path := filepath.Join(dir, "fixture.bin")
	if err := os.WriteFile(path, body, 0600); err != nil {
		t.Fatal(err)
	}
	started, release := make(chan struct{}), make(chan struct{})
	var unblock sync.Once
	defer unblock.Do(func() { close(release) })
	accepted := make(chan []string, 1)
	go func() {
		matches, _ := analyzeStored(path, ComputeHashes(body).SHA256, func() ([]byte, func(), error) {
			close(started)
			<-release
			return body, func() {}, nil
		}, nil)
		accepted <- matches
	}()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("accepted job did not start")
	}
	finished := make(chan error, 1)
	go func() {
		analysisErr, persistenceErr := FinishAnalysis()
		finished <- errors.Join(analysisErr, persistenceErr)
	}()
	for deadline := time.Now().Add(5 * time.Second); ; {
		m.mu.Lock()
		closing := m.closing
		m.mu.Unlock()
		if closing {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("analysis did not close admission")
		}
		time.Sleep(time.Millisecond)
	}
	if matches, classification := analyzeStored(path, "late", nil, nil); matches != nil || classification != nil {
		t.Fatal("late job was accepted")
	}
	unblock.Do(func() { close(release) })
	if err := <-finished; err != nil {
		t.Fatal(err)
	}
	if matches := <-accepted; len(matches) != 1 || matches[0] != "fixture-match" {
		t.Fatal("shutdown discarded accepted work", matches)
	}
}

func TestAnalysisCacheDoesNotReloadArtifact(t *testing.T) {
	old := GetGlobalConfig()
	SetGlobalConfig(GetDefaultConfig())
	t.Cleanup(func() { SetGlobalConfig(old) })
	dir := t.TempDir()
	if err := StartAnalysis(dir, "cache-load"); err != nil {
		t.Fatal(err)
	}
	defer FinishAnalysis()
	currentAnalysis().yara = fixtureAnalyzer{}
	body := []byte("artifact fixture")
	digest := ComputeHashes(body).SHA256
	path := filepath.Join(dir, "fixture.bin")
	if err := os.WriteFile(path, body, 0600); err != nil {
		t.Fatal(err)
	}
	loaded, released := 0, 0
	load := func() ([]byte, func(), error) {
		loaded++
		return body, func() { released++ }, nil
	}
	for range 2 {
		matches, _ := analyzeStored(path, digest, load, nil)
		if len(matches) != 1 || matches[0] != "fixture-match" {
			t.Fatal(matches)
		}
	}
	if loaded != 1 || released != 1 {
		t.Fatalf("loads=%d releases=%d; want one each", loaded, released)
	}
}

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
