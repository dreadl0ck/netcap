package webui

import (
	"context"
	"encoding/json"
	"io"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
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

func TestCaptureWorkerBuffersOnePostCaptureJob(t *testing.T) {
	const jobs = 5
	s := &Server{jobQueue: make(chan *AnalysisJob, jobs), shutdownChan: make(chan struct{})}
	captured, completed := make(chan struct{}, jobs), make(chan struct{}, jobs)
	release := make(chan struct{})
	for range jobs {
		s.jobQueue <- &AnalysisJob{processingDone: func() { completed <- struct{}{} }}
	}
	close(s.jobQueue)
	s.wg.Add(1)
	go s.processJobs(func(job *AnalysisJob) {
		job.postCapture = func() { <-release }
		captured <- struct{}{}
	})
	defer func() {
		close(release)
		s.wg.Wait()
		if len(completed) != jobs {
			t.Errorf("released %d of %d jobs", len(completed), jobs)
		}
	}()
	deadline := time.After(5 * time.Second)
	for range 4 {
		select {
		case <-captured:
		case <-deadline:
			t.Fatal("capture stalled before filling the post-processing backlog")
		}
	}
	select {
	case <-captured:
		t.Fatal("capture exceeded the bounded backlog")
	case <-completed:
		t.Fatal("job ownership released while completion was blocked")
	case <-time.After(20 * time.Millisecond):
	}
}

func TestSmallAnalysisRecoversAfterSaturatedHandoff(t *testing.T) {
	s, smallInput, smallDir := reanalysisFixture(t)
	delete(s.completedFiles, smallInput)
	s.fileBPFFilters = make(map[string]string)
	s.shutdownChan = make(chan struct{})
	s.jobQueue = make(chan *AnalysisJob, 4)
	s.rulesConfig = &rules.Config{Rules: []*rules.Rule{{Name: "get", Type: "HTTP", Expression: "Method == 'GET'", Enabled: true}}}
	writeTimelineAuditFile(t, smallDir, "HTTP", types.Type_NC_HTTP, []proto.Message{&types.HTTP{Timestamp: 1, Method: "GET"}})

	started := make(chan string, 3)
	finished := make(chan string, 4)
	smallCaptured := make(chan struct{})
	cleanup := make(chan struct{})
	gates := map[string]chan struct{}{"first": make(chan struct{}), "second": make(chan struct{}), "buffered": make(chan struct{})}
	for _, name := range []string{"first", "second", "buffered", smallInput} {
		job := &AnalysisJob{InputFile: name, processingDone: func() { finished <- name }}
		if name == smallInput {
			job.OutputDir = smallDir
		}
		s.jobQueue <- job
	}
	close(s.jobQueue)
	s.wg.Add(1)
	go s.processJobs(func(job *AnalysisJob) {
		if job.InputFile == smallInput {
			s.finishCaptureJob(job, time.Second)
			close(smallCaptured)
			return
		}
		job.postCapture = func() {
			started <- job.InputFile
			select {
			case <-gates[job.InputFile]:
			case <-cleanup:
			}
		}
	})
	t.Cleanup(func() { close(cleanup); s.wg.Wait() })
	deadline := time.After(5 * time.Second)
	active := make(map[string]bool)
	for range 2 {
		select {
		case name := <-started:
			active[name] = true
		case <-deadline:
			t.Fatal("completion workers did not fill")
		}
	}
	if !active["first"] || !active["second"] {
		t.Fatalf("incorrect jobs running at saturation: %v", active)
	}
	select {
	case <-smallCaptured:
	case <-deadline:
		t.Fatal("small capture did not reach the full handoff")
	}
	select {
	case name := <-finished:
		t.Fatalf("job %q finished while both workers were held", name)
	default:
	}
	close(gates["first"])
	select {
	case name := <-started:
		if name != "buffered" {
			t.Fatalf("buffered job was overtaken by %q", name)
		}
	case <-deadline:
		t.Fatal("buffered job did not resume when a worker opened")
	}
	resumed := time.Now()
	close(gates["buffered"])
	for _, expected := range []string{"first", "buffered", smallInput} {
		select {
		case name := <-finished:
			if name != expected {
				t.Fatalf("completed %q, want %q", name, expected)
			}
		case <-deadline:
			t.Fatalf("%q did not complete with the second worker still occupied", expected)
		}
	}
	t.Logf("small completion after releasing buffered work: %s", time.Since(resumed))
	s.mu.RLock()
	done := s.completedFiles[smallInput]
	s.mu.RUnlock()
	if !done || timelineIndexFor(smallDir).State != timelineStateReady {
		t.Fatal("small analysis did not publish a ready timeline")
	}
	reader, err := NewAuditRecordReader(filepath.Join(smallDir, "Alert.ncap.gz"))
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	if _, err := reader.ReadHeader(); err != nil {
		t.Fatal(err)
	}
	if _, err := reader.NextRecord(); err != nil {
		t.Fatal(err)
	}
	if _, err := reader.NextRecord(); err != io.EOF {
		t.Fatalf("small analysis did not publish exactly one alert: %v", err)
	}
}

func TestQueuedAnalysesKeepAdmittedRulesAfterEdit(t *testing.T) {
	s, input, _ := reanalysisFixture(t)
	s.shutdownChan = make(chan struct{})
	rule := &rules.Rule{Name: "before-edit", Type: "HTTP", Expression: "Method == 'GET'", Enabled: true}
	s.rulesConfig = &rules.Config{Rules: []*rules.Rule{rule}}
	for i := range 2 {
		job := &AnalysisJob{InputFile: input, OutputDir: t.TempDir()}
		writeTimelineAuditFile(t, job.OutputDir, "HTTP", types.Type_NC_HTTP, []proto.Message{
			&types.HTTP{Timestamp: 1, Method: "GET"},
			&types.HTTP{Timestamp: 2, Method: "POST"},
		})
		if err := s.enqueueAnalysis(job, false); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(job.processingDone)
		if i == 0 {
			s.rulesConfigMutex.Lock()
			rule.Name, rule.Expression = "after-edit", "Method == 'POST'"
			s.rulesConfigMutex.Unlock()
		}
	}
	for i, name := range []string{"before-edit", "after-edit"} {
		job := <-s.jobQueue
		if err := s.executeRulesForJob(job); err != nil {
			t.Fatal(err)
		}
		job.processingDone()
		r, err := NewAuditRecordReader(filepath.Join(job.OutputDir, "Alert.ncap.gz"))
		if err != nil {
			t.Fatal(err)
		}
		defer r.Close()
		if _, err := r.ReadHeader(); err != nil {
			t.Fatal(err)
		}
		row, err := r.NextRecord()
		alert, ok := row.(*types.Alert)
		if err != nil || !ok || alert.RuleName != name || alert.Timestamp != int64(i+1) {
			t.Fatalf("wanted %s on record %d, got %v (%v)", name, i+1, row, err)
		}
		if _, err := r.NextRecord(); err != io.EOF {
			t.Fatalf("expected one alert from %s: %v", name, err)
		}
	}
}

func TestCaptureWorkerCompletesSmallAnalysisWhileRegularTimelineWaits(t *testing.T) {
	testCaptureWorkerCompletesSmallAnalysis(t, false)
}

func TestCaptureWorkerCompletesSmallAnalysisDuringLargeRuleReplay(t *testing.T) {
	testCaptureWorkerCompletesSmallAnalysis(t, true)
}

func TestSmallAnalysisQueuedDuringTwoActiveRuleReplays(t *testing.T) {
	s, smallInput, smallDir := reanalysisFixture(t)
	delete(s.completedFiles, smallInput)
	s.fileBPFFilters = make(map[string]string)
	s.shutdownChan = make(chan struct{})
	s.jobQueue = make(chan *AnalysisJob, 3)
	s.rulesConfig = &rules.Config{Rules: []*rules.Rule{{Name: "get", Type: "HTTP", Expression: "Method == 'GET'", Enabled: true}}}
	match := &types.HTTP{Timestamp: 1, Method: "GET"}
	miss := &types.HTTP{Timestamp: 2, Method: "POST", URL: "/fixture"}
	const records = 150_000
	rows := make([]proto.Message, records)
	rows[0] = match
	for i := 1; i < len(rows); i++ {
		rows[i] = miss
	}
	finished := make(chan string, 3)
	large := make([]captureSelection, 2)
	for i := range large {
		dir := t.TempDir()
		input := filepath.Join(dir, "large.pcap")
		writeTimelineAuditFilePlain(t, dir, "HTTP", types.Type_NC_HTTP, rows)
		large[i] = captureSelection{InputFile: input, OutputDir: dir}
		s.jobQueue <- &AnalysisJob{InputFile: input, OutputDir: dir, processingDone: func() { finished <- input }}
	}
	writeTimelineAuditFile(t, smallDir, "HTTP", types.Type_NC_HTTP, []proto.Message{match})
	s.wg.Add(1)
	go s.processJobs(func(job *AnalysisJob) { s.finishCaptureJob(job, time.Second) })
	defer func() { s.stopProcessingAdmission(); s.wg.Wait() }()
	deadline := time.After(30 * time.Second)
	for {
		s.mu.RLock()
		both := s.postCapturePhases[large[0].OutputDir] == "rules" && s.postCapturePhases[large[1].OutputDir] == "rules"
		s.mu.RUnlock()
		if both {
			break
		}
		select {
		case input := <-finished:
			t.Fatalf("%s completed before both workers entered rule replay", input)
		case <-deadline:
			t.Fatal("both workers did not enter rule replay")
		case <-time.After(time.Millisecond):
		}
	}
	started := time.Now()
	s.jobQueue <- &AnalysisJob{InputFile: smallInput, OutputDir: smallDir, processingDone: func() { finished <- smallInput }}
	outputs := map[string]string{smallInput: smallDir, large[0].InputFile: large[0].OutputDir, large[1].InputFile: large[1].OutputDir}
	for range 3 {
		select {
		case input := <-finished:
			if input == smallInput {
				t.Logf("tiny completion after queueing during two %d-record replays: %s", records, time.Since(started))
			}
			dir, ok := outputs[input]
			delete(outputs, input)
			s.mu.RLock()
			complete := s.completedFiles[input]
			s.mu.RUnlock()
			if !ok || !complete || timelineIndexFor(dir).State != timelineStateReady {
				t.Fatalf("%s did not publish exactly one successful completion with a ready timeline", input)
			}
			r, err := NewAuditRecordReader(filepath.Join(dir, "Alert.ncap.gz"))
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			if _, err := r.ReadHeader(); err != nil {
				t.Fatal(err)
			}
			alert, err := r.NextAs[*types.Alert]()
			if err != nil || alert.RuleName != "get" || alert.Timestamp != match.Timestamp {
				t.Fatalf("%s: wrong alert %v, %v", input, alert, err)
			}
			if _, err := r.NextRecord(); err != io.EOF {
				t.Fatalf("%s: expected exactly one alert: %v", input, err)
			}
		case <-deadline:
			t.Fatalf("jobs did not complete: %v", outputs)
		}
	}
}

func testCaptureWorkerCompletesSmallAnalysis(t *testing.T, ruleLoad bool) {
	t.Helper()
	s, smallInput, smallDir := reanalysisFixture(t)
	delete(s.completedFiles, smallInput)
	s.fileBPFFilters = make(map[string]string)
	s.shutdownChan = make(chan struct{})
	s.rulesConfig = &rules.Config{Rules: []*rules.Rule{{Name: "get", Type: "HTTP", Expression: "Method == 'GET'", Enabled: true}}}
	writeTimelineAuditFile(t, smallDir, "HTTP", types.Type_NC_HTTP, []proto.Message{&types.HTTP{Timestamp: 1, Method: "GET"}})
	largeDir := t.TempDir()
	largeInput := filepath.Join(largeDir, "large.pcap")
	record := &types.HTTP{Timestamp: 2, Method: "POST", URL: "/" + strings.Repeat("x", 1024)}
	count := 512
	waitPhase := "timeline"
	if ruleLoad {
		count = 150000
		waitPhase = "rules"
		record.URL = "/fixture"
	}
	rows := make([]proto.Message, count)
	for i := range rows {
		rows[i] = record
	}
	writeTimelineAuditFilePlain(t, largeDir, "HTTP", types.Type_NC_HTTP, rows)
	largeDone, smallDone := make(chan struct{}), make(chan struct{})
	s.jobQueue <- &AnalysisJob{InputFile: largeInput, OutputDir: largeDir, processingDone: func() { close(largeDone) }}
	held := !ruleLoad
	if held {
		timelineBuildSlot <- struct{}{}
	}
	s.wg.Add(1)
	go s.processJobs(func(job *AnalysisJob) { s.finishCaptureJob(job, time.Second) })
	defer func() {
		if held {
			<-timelineBuildSlot
		}
		s.stopProcessingAdmission()
		s.wg.Wait()
	}()
	deadline := time.After(15 * time.Second)
	for {
		phase, _ := s.selectedAnalysisPhase(captureSelection{InputFile: largeInput, OutputDir: largeDir})
		if phase == waitPhase {
			break
		}
		select {
		case <-largeDone:
			t.Fatalf("large job finished before observing phase %s", waitPhase)
		case <-deadline:
			t.Fatalf("large job never reached phase %s", waitPhase)
		case <-time.After(time.Millisecond):
		}
	}
	started := time.Now()
	s.jobQueue <- &AnalysisJob{InputFile: smallInput, OutputDir: smallDir, processingDone: func() { close(smallDone) }}
	select {
	case <-smallDone:
	case <-deadline:
		t.Fatalf("small job did not complete while large job was in phase %s", waitPhase)
	}
	if ruleLoad {
		phase, _ := s.selectedAnalysisPhase(captureSelection{InputFile: largeInput, OutputDir: largeDir})
		if phase != "rules" {
			t.Fatalf("large replay reached phase %s before small completion", phase)
		}
		t.Logf("small completion under %d-record rule replay: %s", count, time.Since(started))
	}
	select {
	case <-largeDone:
		t.Fatal("large job completed before the small job")
	default:
	}
	s.mu.RLock()
	smallCompleted := s.completedFiles[smallInput]
	s.mu.RUnlock()
	if !smallCompleted || timelineIndexFor(smallDir).State != timelineStateReady {
		t.Fatal("small job did not publish completed analysis with a ready timeline")
	}
	reader, err := NewAuditRecordReader(filepath.Join(smallDir, "Alert.ncap.gz"))
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	if _, err := reader.ReadHeader(); err != nil {
		t.Fatal(err)
	}
	if _, err := reader.NextRecord(); err != nil {
		t.Fatal(err)
	}
	if _, err := reader.NextRecord(); err != io.EOF {
		t.Fatalf("small job did not publish exactly one alert: %v", err)
	}
	if held {
		<-timelineBuildSlot
		held = false
	}
	select {
	case <-largeDone:
	case <-deadline:
		t.Fatal("large job did not finish once capacity returned")
	}
	if !s.completedFiles[largeInput] {
		t.Fatal("large job did not publish completion")
	}
}

func TestCaptureWorkerShutdownCancelsBacklog(t *testing.T) {
	s := &Server{
		jobQueue: make(chan *AnalysisJob, 5), shutdownChan: make(chan struct{}),
		fileErrors: make(map[string]FileError),
	}
	names := []string{"active-1", "active-2", "handoff", "capture", "queued"}
	captured, started, released := make(chan string, 5), make(chan string, 5), make(chan string, 5)
	release := make(chan struct{})
	for _, name := range names {
		s.jobQueue <- &AnalysisJob{InputFile: name, processingDone: func() { released <- name }}
	}
	s.wg.Add(1)
	go s.processJobs(func(job *AnalysisJob) {
		job.postCapture = func() {
			started <- job.InputFile
			<-release
		}
		captured <- job.InputFile
	})
	completed := make(map[string]int)
	t.Cleanup(func() {
		s.stopProcessingAdmission()
		close(release)
		done := make(chan struct{})
		go func() { s.wg.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("workers did not stop after release")
			return
		}
		close(released)
		for name := range released {
			completed[name]++
		}
		for _, name := range names {
			if completed[name] != 1 {
				t.Errorf("%s released %d times, want once", name, completed[name])
			}
		}
		if len(started) != 0 || len(captured) != 0 {
			t.Error("backlog started after shutdown")
		}
		if failure, ok := s.GetFileError("handoff"); !ok || failure.Error != "Analysis canceled during shutdown" {
			t.Errorf("handoff cancellation missing: %+v", failure)
		}
	})
	deadline := time.After(5 * time.Second)
	for _, name := range names[:4] {
		select {
		case got := <-captured:
			if got != name {
				t.Fatalf("captured %q, want %q", got, name)
			}
		case <-deadline:
			t.Fatal("capture did not reach handoff backpressure")
		}
	}
	for range 2 {
		select {
		case <-started:
		case <-deadline:
			t.Fatal("completion worker never started")
		}
	}
	s.stopProcessingAdmission()
	for range 2 {
		select {
		case name := <-released:
			completed[name]++
		case <-deadline:
			t.Fatal("shutdown did not release capture and queued jobs while workers were blocked")
		}
	}
	for _, name := range names[3:] {
		if failure, ok := s.GetFileError(name); !ok || failure.Error != "Analysis canceled during shutdown" || completed[name] != 1 {
			t.Fatalf("%s: cancellation=%+v, releases=%d", name, failure, completed[name])
		}
	}
}

func TestAnalysisCompletionRejectsTruncatedTimelineTrack(t *testing.T) {
	s, input, dir := reanalysisFixture(t)
	delete(s.completedFiles, input)
	s.rulesConfig = &rules.Config{}
	if err := os.Remove(filepath.Join(dir, "HTTP.ncap.gz")); err != nil {
		t.Fatal(err)
	}
	path := writeTimelineAuditFilePlain(t, dir, "HTTP", types.Type_NC_HTTP, []proto.Message{&types.HTTP{Method: "GET"}})
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, writeErr := f.Write([]byte{4}) // Declared record body is missing.
	if closeErr := f.Close(); writeErr != nil || closeErr != nil {
		t.Fatal(writeErr, closeErr)
	}
	err = s.completeAnalysis(&AnalysisJob{InputFile: input, OutputDir: dir}, time.Second)
	if err == nil || !strings.Contains(err.Error(), "index HTTP: unexpected EOF") || s.completedFiles[input] {
		t.Fatalf("damaged audit passed completion: error=%v completed=%t", err, s.completedFiles[input])
	}
}

func TestAnalysisCompletionRejectsMislabeledTimelineTrack(t *testing.T) {
	s, input, dir := reanalysisFixture(t)
	delete(s.completedFiles, input)
	s.rulesConfig = &rules.Config{}
	writeTimelineAuditFile(t, dir, "HTTP", types.Type_NC_UDP, []proto.Message{&types.UDP{Timestamp: 1}})
	err := s.completeAnalysis(&AnalysisJob{InputFile: input, OutputDir: dir}, time.Second)
	if err == nil || !strings.Contains(err.Error(), "index HTTP: unexpected audit header type NC_UDP for HTTP") || s.completedFiles[input] {
		t.Fatalf("mislabeled audit passed completion: error=%v completed=%t", err, s.completedFiles[input])
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
		if phase, _ := s.selectedAnalysisPhase(captureSelection{OutputDir: dir, InputFile: input}); phase == "timeline" && timelineIndexFor(dir).State == timelineStateIndexing {
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
	assertPhase := func(phase, generation string) {
		t.Helper()
		response := httptest.NewRecorder()
		request := httptest.NewRequest("GET", "/api/audit-stats", nil)
		request = request.WithContext(context.WithValue(request.Context(), captureSelectionKey{}, captureSelection{InputFile: input, OutputDir: dir}))
		query := request.URL.Query()
		query.Set("inputFile", input)
		request.URL.RawQuery = query.Encode()
		s.handleAuditStats(response, request)
		var stats AuditStatsResponse
		if err := json.Unmarshal(response.Body.Bytes(), &stats); response.Code != 200 || err != nil || stats.AnalysisPhase != phase || stats.TimelineGeneration != generation {
			t.Fatalf("phase %s generation %s: %d %s (%v)", phase, generation, response.Code, response.Body, err)
		}
	}
	assertPhase("timeline", "")
	// A retained completion marker must not advertise readiness during a rebuild.
	s.mu.Lock()
	s.completedFiles[input] = true
	s.mu.Unlock()
	assertPhase("timeline", "")
	s.mu.Lock()
	delete(s.completedFiles, input)
	s.mu.Unlock()
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
	assertPhase("completed", wantGeneration)
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
	for _, failure := range []string{"engine", "writer", "read", "dangling-audit", "unknown-type", "timeline"} {
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
			case "unknown-type":
				rule.Type = "MissingAuditType"
			case "writer":
				if err := os.Mkdir(filepath.Join(dir, "Alert.ncap.gz"), 0700); err != nil {
					t.Fatal(err)
				}
			case "read":
				if err := os.WriteFile(filepath.Join(dir, "HTTP.ncap.gz"), []byte("corrupt"), 0600); err != nil {
					t.Fatal(err)
				}
			case "dangling-audit":
				preferred := filepath.Join(dir, "HTTP.ncap.gz")
				if err := os.Remove(preferred); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(filepath.Join(dir, "absent"), preferred); err != nil {
					t.Skipf("symlink unavailable: %v", err)
				}
			}
			err := s.completeAnalysis(&AnalysisJob{InputFile: input, OutputDir: dir, SessionID: "failed"}, time.Second)
			if err == nil {
				t.Fatal("post-analysis failure accepted")
			}
			if failure == "dangling-audit" && !strings.Contains(err.Error(), "post-analysis rules: open HTTP audit") {
				t.Fatalf("dangling audit did not fail during rule replay: %v", err)
			}
			if failure == "unknown-type" && !strings.Contains(err.Error(), "post-analysis rules: unknown audit type") {
				t.Fatalf("unknown audit type did not fail during rule replay: %v", err)
			}
			if s.completedFiles[input] {
				t.Fatal("failed analysis published complete")
			}
		})
	}
}
