package webui

import "context"

func (s *Server) readAlertsFromFile(filePath string) ([]AlertResponse, error) {
	return s.readAlertAudit(context.Background(), filePath)
}

func (s *Server) readAlertAudit(ctx context.Context, filePath string) ([]AlertResponse, error) {
	return s.scanAlertAudit(ctx, filePath, maxCollectionPageScanBytes, maxCollectionPageRows, maxCollectionPageScanBytes, nil)
}
