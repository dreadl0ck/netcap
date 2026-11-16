package webui

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/dreadl0ck/netcap/types"
	"github.com/gogo/protobuf/proto"
)

func TestSecretDeviceCaptureSelection(t *testing.T) {
	a, b := t.TempDir(), t.TempDir()
	writeTimelineAuditFile(t, a, "Secret", types.Type_NC_Secret, []proto.Message{&types.Secret{User: "user-A"}})
	writeTimelineAuditFile(t, b, "Secret", types.Type_NC_Secret, []proto.Message{&types.Secret{User: "user-B"}})
	writeTimelineAuditFile(t, a, "DeviceProfile", types.Type_NC_DeviceProfile, []proto.Message{&types.DeviceProfile{MacAddr: "device-A"}})
	writeTimelineAuditFile(t, b, "DeviceProfile", types.Type_NC_DeviceProfile, []proto.Message{&types.DeviceProfile{MacAddr: "device-B"}})
	s := &Server{outDir: b, activeInputFile: "/b.pcap", inputFiles: []string{"/a.pcap", "/b.pcap"},
		fileOutputDirs: map[string]string{"/a.pcap": a, "/b.pcap": b}, fileIDToPath: map[string]string{"a": "/a.pcap", "b": "/b.pcap"}}
	for name, handler := range map[string]http.HandlerFunc{"secrets": s.handleSecrets, "devices": s.handleDevices} {
		t.Run(name, func(t *testing.T) {
			for _, tc := range []struct {
				query        string
				status       int
				want, absent string
			}{
				{"sessionId=a", 200, "-A", "-B"},
				{"inputFile=/a.pcap", 200, "-A", "-B"},
				{"sessionId=b", 200, "-B", "-A"},
				{"sessionId=missing", 404, "", "-B"},
				{"sessionId=a&inputFile=/b.pcap", 409, "", "-B"},
			} {
				w := httptest.NewRecorder()
				handler(w, httptest.NewRequest(http.MethodGet, "/api/"+name+"?"+tc.query, nil))
				if w.Code != tc.status || !strings.Contains(w.Body.String(), tc.want) || strings.Contains(w.Body.String(), tc.absent) {
					t.Fatalf("%s: status=%d body=%s", tc.query, w.Code, w.Body.String())
				}
			}
			// An active-capture change after middleware resolution cannot rebind this request.
			w := httptest.NewRecorder()
			s.captureSelectionMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				s.mu.Lock()
				s.outDir, s.activeInputFile = b, "/b.pcap"
				s.mu.Unlock()
				handler(w, r)
			})).ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/"+name+"?sessionId=a", nil))
			if w.Code != 200 || !strings.Contains(w.Body.String(), "-A") || strings.Contains(w.Body.String(), "-B") {
				t.Fatal(w.Body.String())
			}
		})
	}
	manager := NewSessionManager(10, 60, 10)
	manager.AddSession(&SessionInfo{SessionID: "a", IP: "192.0.2.1", InputFile: "a.pcap", OutputDir: a})
	manager.AddSession(&SessionInfo{SessionID: "b", IP: "192.0.2.2", InputFile: "b.pcap", OutputDir: b})
	s.isServiceMode, s.sessionManager, s.currentSession = true, manager, "b"
	for name, handler := range map[string]http.HandlerFunc{"secrets": s.handleSecrets, "devices": s.handleDevices} {
		for _, tc := range []struct {
			id     string
			status int
		}{{"a", 200}, {"b", 403}, {"unknown", 404}} {
			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodGet, "/api/"+name+"?sessionId="+tc.id, nil)
			r.RemoteAddr = "192.0.2.1:4242"
			handler(w, r)
			if w.Code != tc.status || strings.Contains(w.Body.String(), "-B") {
				t.Fatalf("%s %s: %d %s", name, tc.id, w.Code, w.Body.String())
			}
		}
	}
}
