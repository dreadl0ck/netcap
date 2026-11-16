package webui

import "net/http"

func (s *Server) captureReadAdmission(selection captureSelection, allowPending bool) error {
	s.mu.RLock()
	service, manager := s.isServiceMode, s.sessionManager
	if !service {
		failure, failed := s.fileErrors[selection.InputFile]
		completed := s.completedFiles[selection.InputFile]
		_, upload := s.localUploads[selection.InputFile]
		_, child := s.childAnalyses[selection.InputFile]
		s.mu.RUnlock()
		if failed {
			return selectionError(http.StatusUnprocessableEntity, "Analysis failed: "+failure.Error)
		}
		if !completed && (upload || child) && !allowPending {
			return selectionError(http.StatusConflict, "Analysis is not ready; wait for completion before querying records")
		}
		return nil
	}
	s.mu.RUnlock()
	if manager == nil {
		return selectionError(http.StatusServiceUnavailable, "Analysis state is unavailable")
	}
	manager.mu.RLock()
	defer manager.mu.RUnlock()
	session, exists := manager.sessions[selection.SessionID]
	if !exists {
		return selectionError(http.StatusNotFound, "Unknown capture session")
	}
	if session.Status == StatusFailed {
		return selectionError(http.StatusUnprocessableEntity, "Analysis failed: "+session.ErrorMessage)
	}
	if session.Status != StatusCompleted && !allowPending {
		return selectionError(http.StatusConflict, "Analysis is not ready; wait for completion before querying records")
	}
	return nil
}
