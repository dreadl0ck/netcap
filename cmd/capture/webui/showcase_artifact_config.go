package webui

import (
	"fmt"
	"os"

	"github.com/dreadl0ck/netcap/internal/decoder/stream/file"
)

func (s *Server) captureArtifactConfig(sessionID string) ([]byte, error) {
	path := os.Getenv("NC_SHOWCASE_FILE_CONFIG")
	if path != "" && s.isServiceMode && s.sessionManager != nil {
		if session, ok := s.sessionManager.GetSession(sessionID); ok && session.IsPreloaded {
			cfg, err := file.LoadConfig(path)
			if err != nil {
				return nil, fmt.Errorf("showcase artifact profile: %w", err)
			}
			return encodeArtifactConfig(cfg)
		}
	}
	return snapshotArtifactConfig()
}
