//go:build !appstore

package webui

import (
	"net/http"
	"path/filepath"
	"runtime"
)

func (s *Server) handleLiveInterfaces(w http.ResponseWriter, _ *http.Request) {
	if s.isServiceMode {
		http.Error(w, "host capture is local-mode only", 403)
		return
	}
	devices, err := liveInterfaces()
	if err != nil {
		http.Error(w, err.Error(), 503)
		return
	}
	path, prefix := captureHelperCommand()
	if path != "" {
		path, err = filepath.Abs(path)
		if err != nil {
			path = ""
		}
	}
	RespondJSON(w, 200, map[string]any{"interfaces": devices, "helperPath": path, "prefix": prefix, "platform": runtime.GOOS})
}
