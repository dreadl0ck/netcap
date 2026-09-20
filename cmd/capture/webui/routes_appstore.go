//go:build appstore

package webui

import "net/http"

// The App Store edition accepts user-selected capture files only. Active
// capture and packet-injection handlers are not registered or linked.
func registerEditionRoutes(_ *http.ServeMux, _ *Server) {}
