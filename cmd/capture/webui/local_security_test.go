package webui

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestLocalAPIBoundary(t *testing.T) {
	t.Setenv("NC_CORS_ALLOWED_ORIGINS", "")
	s := &Server{addr: "localhost:8080", localAccessToken: "synthetic-per-run-token"}
	for _, tc := range []struct {
		name, method, host, origin, authorization string
		want                                      int
	}{
		{"anonymous secrets", "GET", "localhost:8080", "", "", 401},
		{"authorized secrets", "GET", "localhost:8080", "", "Bearer synthetic-per-run-token", 204},
		{"wrong credential", "GET", "localhost:8080", "", "Bearer wrong", 401},
		{"wrong scheme", "GET", "localhost:8080", "", "synthetic-per-run-token", 401},
		{"rebinding", "GET", "attacker.example:8080", "", "Bearer synthetic-per-run-token", 403},
		{"cross origin read", "GET", "localhost:8080", "https://attacker.example", "Bearer synthetic-per-run-token", 403},
		{"simple upload", "POST", "localhost:8080", "https://attacker.example", "", 403},
		{"preflight", "OPTIONS", "localhost:8080", "https://attacker.example", "", 403},
		{"opaque origin", "POST", "localhost:8080", "null", "Bearer synthetic-per-run-token", 403},
		{"same origin", "POST", "localhost:8080", "http://localhost:8080", "Bearer synthetic-per-run-token", 204},
		{"loopback alias", "GET", "127.0.0.1:8080", "", "Bearer synthetic-per-run-token", 204},
		{"wrong port", "GET", "localhost:9090", "", "Bearer synthetic-per-run-token", 403},
	} {
		t.Run(tc.name, func(t *testing.T) {
			called := false
			h := s.localSecurityMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { called = true; w.WriteHeader(204) }))
			r := httptest.NewRequest(tc.method, "http://localhost:8080/api/secrets", nil)
			r.Host = tc.host
			r.Header.Set("Origin", tc.origin)
			r.Header.Set("Authorization", tc.authorization)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != tc.want || called != (tc.want == 204) {
				t.Fatalf("status=%d called=%v; want %d", w.Code, called, tc.want)
			}
			if w.Header().Get("Access-Control-Allow-Origin") == "*" {
				t.Fatal("wildcard CORS")
			}
		})
	}
}

func TestLocalServerProtectsAPI(t *testing.T) {
	t.Setenv("NC_CORS_ALLOWED_ORIGINS", "")
	s := NewServer("127.0.0.1:0", t.TempDir(), nil, "", false, false, false, nil, nil, false)
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := s.Stop(ctx); err != nil {
			t.Error(err)
		}
	})
	client := &http.Client{Timeout: 5 * time.Second}
	for _, authorized := range []bool{false, true} {
		r, err := http.NewRequest("GET", s.GetURL()+"/api/version", nil)
		if err != nil {
			t.Fatal(err)
		}
		if authorized {
			r.Header.Set("Authorization", "Bearer "+s.LocalAccessToken())
		}
		response, err := client.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		want := http.StatusUnauthorized
		if authorized {
			want = http.StatusOK
		}
		if response.StatusCode != want {
			t.Fatalf("authorized=%t: %s", authorized, response.Status)
		}
	}
}

func TestLocalBrowserSignIn(t *testing.T) {
	s := &Server{addr: "localhost:8080", localAccessToken: "synthetic-token"}
	h := s.localSecurityMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) }))
	r := httptest.NewRequest("POST", "http://localhost:8080/auth", strings.NewReader(url.Values{"token": {s.localAccessToken}}.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Origin", "http://localhost:8080")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 303 || w.Header().Get("Location") != "/" {
		t.Fatal(w.Code, w.Header())
	}
	cookies := w.Result().Cookies()
	if len(cookies) != 1 || !cookies[0].HttpOnly || cookies[0].SameSite != http.SameSiteStrictMode {
		t.Fatal("unsafe session cookie", cookies)
	}
	r = httptest.NewRequest("GET", "http://localhost:8080/api/secrets", nil)
	r.AddCookie(cookies[0])
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 204 {
		t.Fatal(w.Code)
	}
	r = httptest.NewRequest("GET", "http://localhost:8080/auth", nil)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if strings.Contains(w.Body.String(), s.localAccessToken) {
		t.Fatal("credential leaked in sign-in page")
	}
}
