package webui

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestServiceModeRejectsNetworkInterfaces(t *testing.T) {
	s := &Server{isServiceMode: true}
	rec := httptest.NewRecorder()
	s.handleNetworkInterfaces(rec, httptest.NewRequest(http.MethodGet, "/api/network-interfaces", nil))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "hardwareAddr") {
		t.Fatalf("service mode leaked interface details: %s", rec.Body.String())
	}

	local := httptest.NewRecorder()
	(&Server{}).handleNetworkInterfaces(local, httptest.NewRequest(http.MethodGet, "/api/network-interfaces", nil))
	if local.Code != http.StatusOK {
		t.Fatalf("local mode status = %d, want 200", local.Code)
	}
}

func TestServiceModeRejectsInjectionWrites(t *testing.T) {
	s := &Server{isServiceMode: true}
	body := `{"name":"test","enabled":false,"action":"log"}`
	for _, tc := range []struct {
		method, path string
		handler      http.HandlerFunc
	}{
		{http.MethodPost, "/api/injection-rules", s.handleInjectionRules},
		{http.MethodPut, "/api/injection-rules/test", s.handleInjectionRule},
		{http.MethodPatch, "/api/injection-rules/test", s.handleInjectionRule},
		{http.MethodDelete, "/api/injection-rules/test", s.handleInjectionRule},
		{http.MethodDelete, "/api/injection-events/clear", s.handleInjectionEventsManage},
	} {
		rec := httptest.NewRecorder()
		tc.handler(rec, httptest.NewRequest(tc.method, tc.path, strings.NewReader(body)))
		if rec.Code != http.StatusForbidden {
			t.Errorf("%s %s status = %d, want 403", tc.method, tc.path, rec.Code)
		}
	}
}
