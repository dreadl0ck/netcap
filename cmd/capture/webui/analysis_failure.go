package webui

func (s *Server) recordAnalysisFailure(job *AnalysisJob, message, errorLogPath string) {
	s.rememberFailedReproduction(job, message)
	if s.sessionManager != nil {
		s.sessionManager.UpdateSessionStatus(job.SessionID, StatusFailed, message, errorLogPath)
		return
	}
	s.SetFileError(job.InputFile, message, errorLogPath)
}
