package webui

import (
	"encoding/json"
	"io"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/internal/rules"
	"github.com/dreadl0ck/netcap/types"
	"github.com/gogo/protobuf/proto"
)

func TestCaptureWorkerHandsOffCompletionWithoutReleasingJobOwnership(t *testing.T) {
	s := &Server{jobQueue: make(chan *AnalysisJob, 2), shutdownChan: make(chan struct{})}
	firstStarted := make(chan struct{})
	secondFinished := make(chan struct{})
	firstFinished := make(chan struct{})
	release := make(chan struct{})
	s.jobQueue <- &AnalysisJob{InputFile: "first", processingDone: func() { close(firstFinished) }}
	s.jobQueue <- &AnalysisJob{InputFile: "second", processingDone: func() { close(secondFinished) }}
	s.wg.Add(1)
	go s.processJobs(func(job *AnalysisJob) {
		job.postCapture = func() {
			if job.InputFile == "first" {
				close(firstStarted)
				<-release
			}
		}
	})
	defer func() { close(release); close(s.shutdownChan); s.wg.Wait() }()
	for _, event := range []<-chan struct{}{firstStarted, secondFinished} {
		select {
		case <-event:
		case <-time.After(5 * time.Second):
			t.Fatal("unrelated completion blocked behind first job")
		}
	}
	select {
	case <-firstFinished:
		t.Fatal("capture worker released the first job before post-processing finished")
	default:
	}
}

func TestAnalysisCompletionWaitsForFinalAlerts(t *testing.T) {
	for _, service := range []bool{false, true} {
		t.Run(map[bool]string{false: "local", true: "service"}[service], func(t *testing.T) {
			s, input, dir := reanalysisFixture(t)
			s.fileBPFFilters = make(map[string]string)
			delete(s.completedFiles, input)
			s.rulesConfig = &rules.Config{Rules: []*rules.Rule{{Name: "all-http", Type: "HTTP", Expression: "true", Enabled: true}}}
			writeTimelineAuditFile(t, dir, "HTTP", types.Type_NC_HTTP, []proto.Message{&types.HTTP{Method: "GET"}})
			job := &AnalysisJob{InputFile: input, OutputDir: dir, SessionID: "analysis"}
			if service {
				s.isServiceMode = true
				s.sessionManager = NewSessionManager(10, 60, 10)
				s.sessionManager.AddSession(&SessionInfo{SessionID: job.SessionID, InputFile: input, OutputDir: dir, Status: StatusProcessing})
			}
			s.rulesConfigMutex.Lock()
			done := make(chan error, 1)
			go func() { done <- s.completeAnalysis(job, time.Second) }()
			select {
			case err := <-done:
				s.rulesConfigMutex.Unlock()
				t.Fatalf("completion bypassed rules barrier: %v", err)
			case <-time.After(30 * time.Millisecond):
			}
			s.mu.RLock()
			completed := s.completedFiles[input]
			s.mu.RUnlock()
			if service {
				session, _ := s.sessionManager.GetSession(job.SessionID)
				completed = session.Status == StatusCompleted
			}
			s.rulesConfigMutex.Unlock()
			if completed {
				t.Fatal("analysis published complete while rules were blocked")
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			if service {
				session, _ := s.sessionManager.GetSession(job.SessionID)
				if session.Status != StatusCompleted {
					t.Fatal("service completion missing")
				}
			} else if !s.completedFiles[input] {
				t.Fatal("local completion missing")
			}
			reader, err := NewAuditRecordReader(filepath.Join(dir, "Alert.ncap.gz"))
			if err != nil {
				t.Fatal(err)
			}
			defer reader.Close()
			if _, err := reader.ReadHeader(); err != nil {
				t.Fatal(err)
			}
			count := 0
			for {
				_, err := reader.NextRecord()
				if err == io.EOF {
					break
				}
				if err != nil {
					t.Fatal("alert writer not finalized", err)
				}
				count++
			}
			if count != 1 {
				t.Fatalf("final alerts=%d want 1", count)
			}
			if status := timelineIndexFor(dir); status.State != timelineStateReady {
				t.Fatalf("completed analysis timeline is %s", status.State)
			}
		})
	}
}

func TestAnalysisCompletionWaitsForTimelineGeneration(t *testing.T) {
	s, input, dir := reanalysisFixture(t)
	s.fileBPFFilters = make(map[string]string)
	s.rulesConfig = &rules.Config{}
	delete(s.completedFiles, input)
	writeTimelineAuditFile(t, dir, "HTTP", types.Type_NC_HTTP, []proto.Message{&types.HTTP{Method: "GET"}})
	timelineSmallBuildSlot <- struct{}{}
	held := true
	defer func() {
		if held {
			<-timelineSmallBuildSlot
		}
	}()
	done := make(chan error, 1)
	go func() {
		done <- s.completeAnalysis(&AnalysisJob{InputFile: input, OutputDir: dir, SessionID: "timeline"}, time.Second)
	}()
	deadline := time.After(2 * time.Second)
	for {
		if status := timelineIndexFor(dir); status.State == timelineStateIndexing {
			break
		}
		select {
		case <-deadline:
			t.Fatal("timeline build did not start")
		default:
			time.Sleep(time.Millisecond)
		}
	}
	select {
	case err := <-done:
		t.Fatalf("completion bypassed timeline barrier: %v", err)
	case <-time.After(30 * time.Millisecond):
	}
	s.mu.RLock()
	completed := s.completedFiles[input]
	s.mu.RUnlock()
	if completed {
		t.Fatal("completed while timeline generation was indexing")
	}
	writeTimelineAuditFile(t, dir, "HTTP", types.Type_NC_HTTP, []proto.Message{&types.HTTP{Method: "GET"}, &types.HTTP{Method: "POST"}})
	wantGeneration, _, err := timelineFingerprint(dir)
	if err != nil {
		t.Fatal(err)
	}
	<-timelineSmallBuildSlot
	held = false
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("completion did not observe the replacement generation")
	}
	if status := timelineIndexFor(dir); status.State != timelineStateReady || status.Index.Generation != wantGeneration {
		t.Fatal("completed with stale timeline", status.State)
	}
}

func TestAnalysisTimelineWaitStopsDuringShutdown(t *testing.T) {
	dir := t.TempDir()
	writeTimelineAuditFile(t, dir, "HTTP", types.Type_NC_HTTP, []proto.Message{&types.HTTP{Method: "GET"}})
	timelineSmallBuildSlot <- struct{}{}
	status := timelineIndexFor(dir)
	defer func() {
		<-timelineSmallBuildSlot
		if status.finished != nil {
			<-status.finished
		}
	}()
	if status.State != timelineStateIndexing || status.finished == nil {
		t.Fatal("fixture timeline did not queue")
	}
	s := &Server{shutdownChan: make(chan struct{})}
	done := make(chan error, 1)
	go func() { done <- s.waitForAnalysisTimeline(dir) }()
	close(s.shutdownChan)
	select {
	case err := <-done:
		if err != errAnalysisStopping {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("shutdown is waiting on the occupied timeline lane")
	}
}

func TestFinalStatisticsUseSelectedAnalysis(t *testing.T) {
	a, b := t.TempDir(), t.TempDir()
	writeTimelineAuditFile(t, a, "HTTP", types.Type_NC_HTTP, []proto.Message{&types.HTTP{Method: "GET"}, &types.HTTP{Method: "POST"}})
	writeTimelineAuditFile(t, b, "Secret", types.Type_NC_Secret, []proto.Message{&types.Secret{User: "b"}})
	s := &Server{outDir: b, activeInputFile: "b.pcap", inputFiles: []string{"a.pcap", "b.pcap"}, fileIDToPath: map[string]string{"a": "a.pcap", "b": "b.pcap"}, fileOutputDirs: map[string]string{"a.pcap": a, "b.pcap": b}}
	for _, tc := range []struct {
		id    string
		count int64
	}{{"a", 2}, {"b", 1}, {"a", 2}} {
		w := httptest.NewRecorder()
		s.handleAuditStats(w, httptest.NewRequest("GET", "/api/audit-stats?sessionId="+tc.id, nil))
		var got AuditStatsResponse
		if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
			t.Fatal(err)
		}
		if int64(got.TotalRecords) != tc.count {
			t.Fatalf("%s stats=%+v", tc.id, got)
		}
	}
}

func TestAnalysisCompletionRejectsRuleFailures(t *testing.T) {
	for _, failure := range []string{"engine", "writer", "read", "timeline"} {
		t.Run(failure, func(t *testing.T) {
			s, input, dir := reanalysisFixture(t)
			delete(s.completedFiles, input)
			rule := &rules.Rule{Name: "all-http", Type: "HTTP", Expression: "true", Enabled: true}
			s.rulesConfig = &rules.Config{Rules: []*rules.Rule{rule}}
			writeTimelineAuditFile(t, dir, "HTTP", types.Type_NC_HTTP, []proto.Message{&types.HTTP{Method: "GET"}})
			switch failure {
			case "timeline":
				s.rulesConfig = &rules.Config{}
				dir = input
			case "engine":
				rule.Expression = "invalid expression ("
			case "writer":
				if err := os.Mkdir(filepath.Join(dir, "Alert.ncap.gz"), 0700); err != nil {
					t.Fatal(err)
				}
			case "read":
				if err := os.WriteFile(filepath.Join(dir, "HTTP.ncap.gz"), []byte("corrupt"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if err := s.completeAnalysis(&AnalysisJob{InputFile: input, OutputDir: dir, SessionID: "failed"}, time.Second); err == nil {
				t.Fatal("post-analysis failure accepted")
			}
			if s.completedFiles[input] {
				t.Fatal("failed analysis published complete")
			}
		})
	}
}
