package webui

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
)

var (
	errAnalysisQueueFull   = errors.New("analysis queue is full")
	errAnalysisStopping    = errors.New("analysis server is stopping")
	errAnalysisUnavailable = errors.New("analysis queue is not available")
)

const (
	captureLookahead   = 8
	smallCaptureBytes  = 64 << 10
	maxCaptureBypasses = 2
)

type captureDispatch struct {
	pending  []*AnalysisJob
	bypasses int
}

func (d *captureDispatch) next(queue <-chan *AnalysisJob, stop <-chan struct{}) *AnalysisJob {
	if ruleReplayCanceled(stop, nil) {
		return nil
	}
	if len(d.pending) == 0 {
		select {
		case job, ok := <-queue:
			if !ok {
				return nil
			}
			d.pending = append(d.pending, job)
		case <-stop:
			return nil
		}
	}
	index := 0
	isSmall := func(job *AnalysisJob) bool {
		return job.reproductionSource.SHA256 != "" && job.reproductionSource.Bytes > 0 && job.reproductionSource.Bytes <= smallCaptureBytes
	}
	if d.bypasses < maxCaptureBypasses && !isSmall(d.pending[0]) {
	fill:
		for len(d.pending) < captureLookahead {
			select {
			case job, ok := <-queue:
				if !ok {
					break fill
				}
				d.pending = append(d.pending, job)
			default:
				break fill
			}
		}
		for i := 1; i < len(d.pending); i++ {
			if isSmall(d.pending[i]) {
				index = i
				break
			}
		}
	}
	if index == 0 {
		d.bypasses = 0
	} else {
		d.bypasses++
	}
	job := d.pending[index]
	copy(d.pending[index:], d.pending[index+1:])
	d.pending[len(d.pending)-1] = nil
	d.pending = d.pending[:len(d.pending)-1]
	return job
}

func (s *Server) processingLocked() bool {
	return s.isProcessing || s.processingWork > 0
}

func (s *Server) beginProcessingWork() func() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.processingStopping {
		return nil
	}
	return s.claimProcessingWorkLocked()
}

func (s *Server) claimProcessingWorkLocked() func() {
	s.processingWork++
	var once sync.Once
	return func() {
		once.Do(func() {
			s.mu.Lock()
			defer s.mu.Unlock()
			s.processingWork--
		})
	}
}

// Admission remains owned while a producer waits for queue capacity.
func (s *Server) enqueueAnalysis(job *AnalysisJob, wait bool) error {
	return s.enqueueAnalysisContext(context.Background(), job, wait)
}

func (s *Server) enqueueAnalysisContext(ctx context.Context, job *AnalysisJob, wait bool) error {
	s.enqueueMu.RLock()
	defer s.enqueueMu.RUnlock()
	if job == nil || s.jobQueue == nil {
		return errAnalysisUnavailable
	}
	if err := ctx.Err(); err != nil {
		job.settings.cleanup()
		return err
	}
	s.mu.Lock()
	if s.processingStopping {
		s.mu.Unlock()
		job.settings.cleanup()
		return errAnalysisStopping
	}
	if s.ownedLiveStarting || s.ownedLive != nil && !s.ownedLive.Completed {
		s.mu.Unlock()
		job.settings.cleanup()
		return errAnalysisUnavailable
	}
	reserved := !wait && cap(s.jobQueue) > 0
	if reserved && len(s.jobQueue)+s.preparingNonblocking >= cap(s.jobQueue) {
		s.mu.Unlock()
		job.settings.cleanup()
		return errAnalysisQueueFull
	}
	if reserved {
		s.preparingNonblocking++
	}
	done := s.claimProcessingWorkLocked()
	s.mu.Unlock()
	accepted := false
	defer func() {
		if reserved {
			s.mu.Lock()
			s.preparingNonblocking--
			s.mu.Unlock()
		}
		if !accepted {
			job.settings.cleanup()
			done()
		}
	}()
	if len(job.ArtifactConfig) == 0 {
		snapshot, err := snapshotArtifactConfig()
		if err != nil {
			return err
		}
		job.ArtifactConfig = snapshot
	}
	if job.settings == nil {
		if job.IncludeDecoders == "" && job.ExcludeDecoders == "" {
			config := s.loadDecoderConfig()
			job.IncludeDecoders = config.IncludeDecoders
			job.ExcludeDecoders = config.ExcludeDecoders
		}
		snapshot, err := s.snapshotJobSettingsContext(ctx)
		if err != nil {
			return err
		}
		snapshot.DPI = job.EnableDPI
		snapshot.BPF = job.BPFFilter
		snapshot.IncludeDecoders = job.IncludeDecoders
		snapshot.ExcludeDecoders = job.ExcludeDecoders
		if job.requireCaptureEvidence {
			snapshot.Runtime.CaptureEvidence = true
		}
		job.settings = snapshot
	}
	job.reproductionSource = snapshotReproductionSource(job.InputFile, ctx.Done(), s.shutdownChan)
	if ruleReplayCanceled(nil, s.shutdownChan) {
		return errAnalysisStopping
	}
	job.reproductionSource.PreviousManifestSHA256 = priorReproductionManifest(ctx, job.OutputDir)
	if err := ctx.Err(); err != nil {
		return err
	}
	job.processingDone = func() { job.settings.cleanup(); done() }
	atomic.AddInt64(&s.jobsScheduled, 1)
	defer func() {
		if !accepted {
			atomic.AddInt64(&s.jobsScheduled, -1)
		}
	}()
	if wait {
		select {
		case s.jobQueue <- job:
			accepted = true
			return nil
		case <-s.shutdownChan:
			return errAnalysisStopping
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if reserved {
		s.preparingNonblocking--
		reserved = false
	}
	if s.processingStopping {
		return errAnalysisStopping
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case <-s.shutdownChan:
		return errAnalysisStopping
	default:
	}
	select {
	case s.jobQueue <- job:
		accepted = true
		return nil
	default:
		return errAnalysisQueueFull
	}
}

func (s *Server) stopProcessingAdmission() {
	s.mu.Lock()
	s.processingStopping = true
	s.mu.Unlock()
	if s.shutdownChan != nil {
		s.shutdownOnce.Do(func() { close(s.shutdownChan) })
	}
	s.enqueueMu.Lock()
	defer s.enqueueMu.Unlock()
	for {
		select {
		case job, ok := <-s.jobQueue:
			if !ok {
				return
			}
			s.recordAnalysisFailure(job, "Analysis canceled during shutdown", "")
			job.processingDone()
		default:
			return
		}
	}
}

func (s *Server) startProcessingWork(run func()) {
	s.enqueueMu.RLock()
	done := s.beginProcessingWork()
	if done == nil {
		s.enqueueMu.RUnlock()
		return
	}
	s.wg.Add(1)
	s.enqueueMu.RUnlock()
	go func() {
		defer s.wg.Done()
		defer done()
		run()
	}()
}
