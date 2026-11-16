package webui

import (
	"fmt"
	"time"
)

func (s *Server) completeAnalysis(job *AnalysisJob, duration time.Duration) error {
	if err := s.executeRulesForJob(job); err != nil {
		return fmt.Errorf("post-analysis rules: %w", err)
	}
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

func (s *Server) waitForAnalysisTimeline(dir string) error {
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	for {
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
		case <-ticker.C:
		}
	}
}
