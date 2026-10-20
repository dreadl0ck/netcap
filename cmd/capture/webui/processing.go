package webui

import (
	"errors"
	"sync"
	"sync/atomic"
)

var (
	errAnalysisQueueFull   = errors.New("analysis queue is full")
	errAnalysisStopping    = errors.New("analysis server is stopping")
	errAnalysisUnavailable = errors.New("analysis queue is not available")
)

func (s *Server) processingLocked() bool {
	return s.isProcessing || s.processingWork > 0
}

func (s *Server) beginProcessingWork() func() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.processingStopping {
		return nil
	}
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
	s.enqueueMu.RLock()
	defer s.enqueueMu.RUnlock()
	if job == nil || s.jobQueue == nil {
		return errAnalysisUnavailable
	}
	done := s.beginProcessingWork()
	if done == nil {
		return errAnalysisStopping
	}
	job.processingDone = done
	atomic.AddInt64(&s.jobsScheduled, 1)
	accepted := false
	defer func() {
		if !accepted {
			atomic.AddInt64(&s.jobsScheduled, -1)
			done()
		}
	}()
	if wait {
		select {
		case s.jobQueue <- job:
			accepted = true
			return nil
		case <-s.shutdownChan:
			return errAnalysisStopping
		}
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
