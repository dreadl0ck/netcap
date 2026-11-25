package webui

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestShowcaseAlertHistoryReadOnly(t *testing.T) {
	s := &Server{isServiceMode: true, sessionManager: NewSessionManager(10, 60, 10)}
	shared, private := t.TempDir(), t.TempDir()
	s.sessionManager.AddSession(&SessionInfo{SessionID: "shared", OutputDir: shared, IsPreloaded: true, Status: StatusCompleted})
	s.sessionManager.AddSession(&SessionInfo{SessionID: "private", OutputDir: private, visitorHash: testVisitorHash("a"), Status: StatusCompleted})
	for _, dir := range []string{shared, private} {
		if err := os.WriteFile(filepath.Join(dir, "Alert.ncap.gz"), []byte("retained"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct {
		path, body string
		handler    http.HandlerFunc
	}{
		{"/api/alerts/clear?sessionId=shared", "", s.handleClearAlerts},
		{"/api/alerts/resolve?sessionId=shared", `{"alertId":"fixture"}`, s.handleResolveAlert},
		{"/api/alerts/unresolve?sessionId=shared", `{"alertId":"fixture"}`, s.handleUnresolveAlert},
		{"/api/rules/offline/execute", `{"sessionId":"shared"}`, s.handleOfflineExecute},
	} {
		for _, visitor := range []string{"a", "b"} {
			r := httptest.NewRequest(http.MethodPost, tc.path, strings.NewReader(tc.body))
			setTestVisitor(r, visitor)
			w := httptest.NewRecorder()
			s.captureSelectionMiddleware(tc.handler).ServeHTTP(w, r)
			if w.Code != http.StatusForbidden {
				t.Fatalf("%s visitor %s: %d %s", tc.path, visitor, w.Code, w.Body.String())
			}
		}
	}
	if data, err := os.ReadFile(filepath.Join(shared, "Alert.ncap.gz")); err != nil || string(data) != "retained" {
		t.Fatalf("shared history changed: %v", err)
	}
	r := httptest.NewRequest(http.MethodPost, "/api/alerts/clear?sessionId=private", nil)
	setTestVisitor(r, "a")
	w := httptest.NewRecorder()
	s.captureSelectionMiddleware(http.HandlerFunc(s.handleClearAlerts)).ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("owner clear: %d %s", w.Code, w.Body.String())
	}
	if _, err := os.Stat(filepath.Join(private, "Alert.ncap.gz")); !os.IsNotExist(err) {
		t.Fatal("owner history was not cleared", err)
	}
}
