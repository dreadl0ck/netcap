package webui

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestMountedMCPAcceptsCaseInsensitiveBearerWithoutAPIElevation(t *testing.T) {
	t.Setenv(EnvMCPAdminToken, "admin")
	s := &Server{addr: "127.0.0.1:8080", localAccessToken: "local"}
	for _, tc := range []struct {
		path, auth string
		status     int
	}{
		{"/mcp", "bearer admin", 200}, {"/mcp", "BEARER admin", 200}, {"/mcp", "Bearer wrong", 401},
		{"/api/status", "bearer local", 200}, {"/api/status", "bearer admin", 401}, {"/api/status", "Basic local", 401},
	} {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("POST", "http://127.0.0.1:8080"+tc.path, nil)
		r.Header.Set("Authorization", tc.auth)
		s.localSecurityMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })).ServeHTTP(w, r)
		if w.Code != tc.status {
			t.Fatalf("%s %s: status %d", tc.path, tc.auth, w.Code)
		}
	}
}

func TestMountedMCPCORSAndBearerScheme(t *testing.T) {
	t.Setenv(EnvMCPAdminToken, "external-mcp-admin")
	s := NewServer("127.0.0.1:0", t.TempDir(), nil, "", false, false, false, nil, nil, false)
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	defer s.Stop(context.Background())
	for _, scheme := range []string{"Bearer", "bearer", "bEaReR"} {
		r, _ := http.NewRequest("POST", s.GetURL()+"/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_features","arguments":{}}}`))
		r.Header.Set("Authorization", scheme+" external-mcp-admin")
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Accept", "application/json, text/event-stream")
		response, err := http.DefaultClient.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := io.ReadAll(response.Body)
		response.Body.Close()
		if err != nil || response.StatusCode != 200 || strings.Contains(string(raw), `"isError":true`) || !strings.Contains(string(raw), "dns-resolution-context") {
			t.Fatalf("%s: %d %s %v", scheme, response.StatusCode, raw, err)
		}
		if response.Header.Get("Access-Control-Allow-Origin") != "" {
			t.Fatal("authenticated response granted unsolicited CORS")
		}
	}
}
