package webui

import "context"

func (s *Server) readAlertsFromFile(filePath string) ([]AlertResponse, error) {
	return s.readAlertAudit(context.Background(), filePath)
}
