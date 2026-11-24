package webui

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

func setTestVisitor(r *http.Request, digit string) {
	r.AddCookie(&http.Cookie{Name: visitorCookie, Value: strings.Repeat(digit, 64)})
}

func testVisitorHash(digit string) string {
	r := httptest.NewRequest("GET", "/", nil)
	setTestVisitor(r, digit)
	return visitorDigest(r)
}

func TestServiceSessionSelectionAndOwnership(t *testing.T) {
	s := &Server{isServiceMode: true, sessionManager: NewSessionManager(10, 60, 10)}
	for _, id := range []string{"a", "b"} {
		s.sessionManager.AddSession(&SessionInfo{SessionID: id, InputFile: id+".pcap", OutputDir: t.TempDir(), Status: StatusCompleted, IsPreloaded: true})
	}
	session := &SessionInfo{SessionID: "private", visitorHash: testVisitorHash("a"), OutputDir: t.TempDir(), Status: StatusCompleted}
	path := filepath.Join(session.OutputDir, "session.json")
	if err := saveSessionMetadata(path, session); err != nil {
		t.Fatal(err)
	}
	loaded, err := loadSessionMetadata(path)
	if err != nil || loaded.visitorHash != session.visitorHash {
		t.Fatal("lost private ownership", err)
	}
	s.sessionManager.AddSession(loaded)
	for _, id := range []string{"a", "b", "a"} {
		w := httptest.NewRecorder()
		s.handleSetDirectory(w, httptest.NewRequest("POST", "/api/set-directory", strings.NewReader(`{"inputFile":"`+id+`.pcap"}`)))
		if w.Code != 200 || !strings.Contains(w.Body.String(), `"sessionId":"`+id+`"`) {
			t.Fatalf("select %s: %d %s", id, w.Code, w.Body.String())
		}
		w = httptest.NewRecorder()
		s.handleStatus(w, httptest.NewRequest("GET", "/api/status?sessionId="+id, nil))
		var status StatusResponse
		if err := json.Unmarshal(w.Body.Bytes(), &status); err != nil || status.SessionID != id || status.ActiveInputFile != id+".pcap" {
			t.Fatalf("status: %+v %v", status, err)
		}
	}
	for _, tc := range []struct { path, identity string; status int }{
		{"/api/status", "a", 200}, {"/api/status/private", "a", 200}, {"/api/status/private", "b", 404},
		{"/api/audit-stats", "a", 503}, {"/api/audit-stats?sessionId=a", "b", 200},
	} {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", tc.path, nil)
		r.RemoteAddr = "192.0.2.10:12345"
		setTestVisitor(r, tc.identity)
		if strings.HasPrefix(tc.path, "/api/audit-stats") {
			s.handleAuditStats(w, r)
		} else {
			s.handleStatus(w, r)
		}
		if w.Code != tc.status || strings.Contains(w.Body.String(), session.visitorHash) || (tc.path == "/api/status" && strings.Contains(w.Body.String(), `"sessionId"`)) {
			t.Fatalf("%s (%s): %d %s", tc.path, tc.identity, w.Code, w.Body.String())
		}
	}
}
