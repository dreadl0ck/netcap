//go:build !appstore

package webui

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDirectRegistersEditionRoutes(t *testing.T) {
	mux := http.NewServeMux()
	registerEditionRoutes(mux, &Server{})
	for _, path := range []string{
		"/api/dbs",
		"/api/dbs/update",
		"/api/dpi",
		"/api/dpi/preferences",
		"/api/yara/status",
		"/api/yara/rules",
		"/api/yara/rules/example.yar",
		"/api/yara/scan",
		"/api/yara/scan-file",
		"/api/service-probes",
		"/api/service-probes/example",
		"/api/service-probes/test",
		"/api/service-probes/export",
		"/api/service-probes/import",
		"/api/injection-rules",
		"/api/injection-rules/example",
		"/api/injection-events",
		"/api/injection-events/clear",
		"/api/injection-stats",
		"/api/injection-actions",
		"/api/network-interfaces",
		"/api/stop-capture",
	} {
		_, pattern := mux.Handler(httptest.NewRequest(http.MethodGet, path, nil))
		if pattern == "" {
			t.Errorf("direct route %s is not registered", path)
		}
	}
}
