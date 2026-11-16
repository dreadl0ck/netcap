package webui

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAnalyticalAdmissionDistinguishesFailedPendingAndEmpty(t *testing.T) {
	for _, service := range []bool{false, true} {
		for _, phase := range []string{"failed", "pending", "completed"} {
			t.Run(map[bool]string{false: "local", true: "service"}[service]+"/"+phase, func(t *testing.T) {
				dir := t.TempDir()
				s := &Server{outDir: dir, activeInputFile: "input", inputFiles: []string{"input"}, fileOutputDirs: map[string]string{"input": dir},
					fileIDToPath: map[string]string{"owned": "input"}, localUploads: map[string]localUpload{"input": {AnalysisID: "owned"}}, completedFiles: map[string]bool{}, fileErrors: map[string]FileError{}}
				status := StatusProcessing
				want := http.StatusConflict
				if phase == "completed" {
					s.completedFiles["input"] = true
					status = StatusCompleted
					want = http.StatusOK
				}
				if phase == "failed" {
					s.fileErrors["input"] = FileError{Error: "synthetic decode failure"}
					status = StatusFailed
					want = http.StatusUnprocessableEntity
				}
				if service {
					s.isServiceMode = true
					s.sessionManager = NewSessionManager(10, 60, 10)
					s.sessionManager.AddSession(&SessionInfo{SessionID: "owned", InputFile: "input", OutputDir: dir, Status: status, ErrorMessage: "synthetic decode failure", IsPreloaded: true})
				}
				for _, path := range []string{"/api/secrets", "/api/devices", "/api/hosts", "/api/audit/HTTP/stream", "/api/files/audit"} {
					w := httptest.NewRecorder()
					h := s.captureSelectionMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("[]")) }))
					h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path+"?sessionId=owned", nil))
					if w.Code != want {
						t.Fatalf("%s got %d want %d: %s", path, w.Code, want, w.Body.String())
					}
					if phase == "failed" && !strings.Contains(w.Body.String(), "synthetic decode failure") {
						t.Fatal("lost failure diagnostic")
					}
					if phase == "completed" && w.Body.String() != "[]" {
						t.Fatal("genuine empty success changed")
					}
				}
			})
		}
	}
}
