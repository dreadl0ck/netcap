package webui

import (
	"fmt"
	"time"
)

func (s *Server) finishCaptureJob(job *AnalysisJob, duration time.Duration) {
	complete := func() {
		if err := s.completeAnalysis(job, duration); err != nil {
			s.recordAnalysisFailure(job, err.Error(), "")
		}
	}
	if job.deferCompletion {
		job.postCapture = complete
		return
	}
	complete()
}

func (s *Server) runPostCapture(job *AnalysisJob) {
	defer job.processingDone()
	defer func() {
		if p := recover(); p != nil {
			s.recordAnalysisFailure(job, fmt.Sprintf("Post-analysis crashed: %v", p), "")
		}
	}()
	select {
	case <-s.shutdownChan:
		s.recordAnalysisFailure(job, "Analysis canceled during shutdown", "")
	default:
		job.postCapture()
	}
}

func (s *Server) completeAnalysis(job *AnalysisJob, duration time.Duration) error {
	s.setPostCapturePhase(job.OutputDir, "rules")
	defer s.setPostCapturePhase(job.OutputDir, "")
	if err := s.executeRulesForJob(job); err != nil {
		return fmt.Errorf("post-analysis rules: %w", err)
	}
	s.setPostCapturePhase(job.OutputDir, "timeline")
	if err := s.waitForAnalysisTimeline(job.OutputDir); err != nil {
		return err
	}
	if s.sessionManager != nil {
		s.sessionManager.UpdateSessionProcessingTime(job.SessionID, duration.Seconds())
		s.sessionManager.UpdateSessionStatus(job.SessionID, StatusCompleted, "", "")
		s.mu.Lock()
		if s.activeInputFile == "" {
			if session, ok := s.sessionManager.GetSession(job.SessionID); ok {
				s.currentSession = job.SessionID
				s.outDir = job.OutputDir
				s.activeInputFile = session.InputFile
			}
		}
		s.mu.Unlock()
	} else {
		s.SetFileProcessingTime(job.InputFile, duration.Seconds())
		s.SetFileOutputDir(job.InputFile, job.OutputDir)
		s.SetFileBPFFilter(job.InputFile, job.BPFFilter)
		s.MarkFileCompleted(job.InputFile)
		s.mu.RLock()
		completed := s.completedFiles[job.InputFile]
		s.mu.RUnlock()
		if !completed {
			return fmt.Errorf("failed to persist analysis completion")
		}
	}
	return nil
}

func (s *Server) setPostCapturePhase(dir, phase string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if phase == "" {
		delete(s.postCapturePhases, dir)
		return
	}
	if s.postCapturePhases == nil {
		s.postCapturePhases = make(map[string]string)
	}
	s.postCapturePhases[dir] = phase
}

func (s *Server) waitForAnalysisTimeline(dir string) error {
	for {
		select {
		case <-s.shutdownChan:
			return errAnalysisStopping
		default:
		}
		status := timelineIndexFor(dir)
		switch status.State {
		case timelineStateReady:
			return nil
		case timelineStateError:
			return fmt.Errorf("post-analysis timeline: %s", status.Err)
		}
		select {
		case <-s.shutdownChan:
			return errAnalysisStopping
		case <-status.finished:
		}
	}
}
