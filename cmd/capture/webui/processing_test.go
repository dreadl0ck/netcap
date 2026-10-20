package webui

import (
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func processingStatus(t *testing.T, server *Server) bool {
	t.Helper()
	response := httptest.NewRecorder()
	server.handleStatus(response, httptest.NewRequest("GET", "/api/status", nil))
	var status StatusResponse
	if err := json.Unmarshal(response.Body.Bytes(), &status); err != nil {
		t.Fatal(err)
	}
	if status.IsProcessing != server.IsProcessing() {
		t.Fatal("API status and manager disagree")
	}
	return status.IsProcessing
}

func processingServer(t *testing.T, hosted bool) *Server {
	t.Helper()
	t.Setenv("NC_APPROVED_WORKSTATIONS", "")
	config := DefaultServiceConfig()
	config.DataDir = t.TempDir()
	return NewServer("127.0.0.1:0", config.DataDir, nil, "", false, false, hosted, config, nil, false)
}

func processingAwait(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !condition() {
		if time.Now().After(deadline) {
			t.Fatal("processing lifecycle did not reach expected state")
		}
		runtime.Gosched()
	}
}

func processingWorker(t *testing.T, server *Server, run func(*AnalysisJob)) {
	t.Helper()
	server.wg.Add(1)
	go server.processJobs(run)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		server.Stop(ctx)
	})
}

func TestProcessingQueueLifecycle(t *testing.T) {
	for _, hosted := range []bool{false, true} {
		server := processingServer(t, hosted)
		first := &AnalysisJob{InputFile: "first"}
		if err := server.enqueueAnalysis(first, false); err != nil {
			t.Fatal(err)
		}
		if !processingStatus(t, server) || len(server.jobQueue) != 1 {
			t.Fatal("scheduled job was not reflected in status")
		}
		started := make(chan string, 2)
		release := make(chan struct{})
		processingWorker(t, server, func(job *AnalysisJob) { started <- job.InputFile; <-release })
		t.Cleanup(func() { close(release) })
		if got := <-started; got != "first" {
			t.Fatal(got)
		}
		if len(server.jobQueue) != 0 || !processingStatus(t, server) {
			t.Fatal("empty queue hid an in-flight job")
		}
		server.SetProcessingComplete()
		if !processingStatus(t, server) {
			t.Fatal("external capture completion hid an in-flight job")
		}
		if err := server.enqueueAnalysis(&AnalysisJob{InputFile: "second"}, false); err != nil {
			t.Fatal(err)
		}
		release <- struct{}{}
		if got := <-started; got != "second" || !processingStatus(t, server) {
			t.Fatal("queued successor was lost")
		}
		release <- struct{}{}
		processingAwait(t, func() bool { return !server.IsProcessing() })
		if processingStatus(t, server) {
			t.Fatal("completed jobs left processing latched")
		}
	}
}

func TestProcessingFailureAndPanicReturnIdle(t *testing.T) {
	server := processingServer(t, false)
	processingWorker(t, server, func(job *AnalysisJob) {
		if job.InputFile == "panic" {
			panic("controlled analysis failure")
		}
		server.recordAnalysisFailure(job, "controlled error", "")
	})
	for _, file := range []string{"error", "panic"} {
		if err := server.enqueueAnalysis(&AnalysisJob{InputFile: file}, true); err != nil {
			t.Fatal(err)
		}
	}
	processingAwait(t, func() bool { return atomic.LoadInt64(&server.jobsProcessed) == 2 && !server.IsProcessing() })
	for _, file := range []string{"error", "panic"} {
		if _, ok := server.GetFileError(file); !ok {
			t.Fatalf("failure was hidden for %s", file)
		}
	}
	if processingStatus(t, server) {
		t.Fatal("failure left processing latched")
	}
}

func TestProcessingCancelDoesNotHideUnwindingWork(t *testing.T) {
	server := processingServer(t, false)
	server.jobQueue = make(chan *AnalysisJob, 1)
	started, release := make(chan struct{}), make(chan struct{})
	releaseWork := sync.OnceFunc(func() { close(release) })
	var calls atomic.Int64
	processingWorker(t, server, func(*AnalysisJob) {
		calls.Add(1)
		close(started)
		<-server.shutdownChan
		<-release
	})
	t.Cleanup(releaseWork)
	if err := server.enqueueAnalysis(&AnalysisJob{InputFile: "active"}, true); err != nil {
		t.Fatal(err)
	}
	<-started
	if err := server.enqueueAnalysis(&AnalysisJob{InputFile: "queued"}, false); err != nil {
		t.Fatal(err)
	}
	if err := server.enqueueAnalysis(&AnalysisJob{InputFile: "full"}, false); !errors.Is(err, errAnalysisQueueFull) {
		t.Fatalf("full queue was accepted: %v", err)
	}
	blocked := make(chan error, 1)
	go func() { blocked <- server.enqueueAnalysis(&AnalysisJob{InputFile: "waiting"}, true) }()
	processingAwait(t, func() bool {
		server.mu.RLock()
		defer server.mu.RUnlock()
		return server.processingWork == 3
	})
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	server.Stop(ctx)
	if err := <-blocked; !errors.Is(err, errAnalysisStopping) {
		t.Fatalf("blocked producer was not canceled: %v", err)
	}
	if len(server.jobQueue) != 0 || !processingStatus(t, server) {
		t.Fatal("shutdown hid actual in-flight work or retained queued work")
	}
	if err := server.enqueueAnalysis(&AnalysisJob{InputFile: "late"}, false); !errors.Is(err, errAnalysisStopping) {
		t.Fatal("admitted work after shutdown")
	}
	releaseWork()
	processingAwait(t, func() bool { return !server.IsProcessing() })
	if calls.Load() != 1 {
		t.Fatal("canceled queued jobs executed")
	}
	if _, ok := server.GetFileError("queued"); !ok {
		t.Fatal("queued cancellation was not recorded")
	}
}

func TestProcessingRulesHandoffStaysBusy(t *testing.T) {
	server := processingServer(t, false)
	started, release := make(chan struct{}), make(chan struct{})
	releaseWork := sync.OnceFunc(func() { close(release) })
	processingWorker(t, server, func(*AnalysisJob) {
		server.startProcessingWork(func() { close(started); <-release })
	})
	t.Cleanup(releaseWork)
	if err := server.enqueueAnalysis(&AnalysisJob{InputFile: "analysis"}, true); err != nil {
		t.Fatal(err)
	}
	<-started
	processingAwait(t, func() bool {
		server.currentJobMutex.RLock()
		defer server.currentJobMutex.RUnlock()
		return server.currentProcessing == nil
	})
	if len(server.jobQueue) != 0 || !processingStatus(t, server) {
		t.Fatal("post-processing was hidden after the capture completed")
	}
	releaseWork()
	processingAwait(t, func() bool { return !server.IsProcessing() })
}

func TestProcessingLiveAndReadOnlyPreview(t *testing.T) {
	server := NewServer("127.0.0.1:0", t.TempDir(), []string{"existing.pcap"}, "", false, false, false, nil, nil, false)
	server.MarkFileCompleted("existing.pcap")
	server.SetLiveMode(true)
	if processingStatus(t, server) {
		t.Fatal("preview/live context alone was treated as active capture")
	}
	server.SetProcessingStarted()
	if !processingStatus(t, server) {
		t.Fatal("live capture admission was hidden")
	}
	server.SetProcessingComplete()
	if processingStatus(t, server) || !server.IsLiveMode() {
		t.Fatal("completed live capture did not become a read-only preview")
	}
}

func TestProcessingConcurrentAdmissionAndStatus(t *testing.T) {
	server := processingServer(t, false)
	var calls atomic.Int64
	processingWorker(t, server, func(*AnalysisJob) { calls.Add(1) })
	var producers sync.WaitGroup
	for range 100 {
		producers.Go(func() {
			if err := server.enqueueAnalysis(&AnalysisJob{InputFile: "concurrent"}, true); err != nil {
				t.Error(err)
			}
		})
	}
	for range 100 {
		server.IsProcessing()
		response := httptest.NewRecorder()
		server.handleStatus(response, httptest.NewRequest("GET", "/api/status", nil))
		var status StatusResponse
		if err := json.Unmarshal(response.Body.Bytes(), &status); err != nil {
			t.Fatal(err)
		}
	}
	producers.Wait()
	processingAwait(t, func() bool { return calls.Load() == 100 && !server.IsProcessing() })
	if atomic.LoadInt64(&server.jobsScheduled) != 100 || atomic.LoadInt64(&server.jobsProcessed) != 100 {
		t.Fatal("admitted jobs were lost")
	}
}

func TestFreshServerProcessingIdle(t *testing.T) {
	t.Setenv("NC_APPROVED_WORKSTATIONS", "")
	for _, hosted := range []bool{false, true} {
		config := DefaultServiceConfig()
		config.DataDir = t.TempDir()
		server := NewServer("127.0.0.1:0", config.DataDir, nil, "", false, false, hosted, config, nil, false)
		if processingStatus(t, server) {
			t.Fatalf("fresh hosted=%v server reports processing without admitted work", hosted)
		}
	}
}
