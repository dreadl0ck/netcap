package webui

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestPublicFontBoundary(t *testing.T) {
	s := &Server{addr: "127.0.0.1:8080", localAccessToken: "test-only-token"}
	next := s.localSecurityMiddleware(s.corsMiddleware(cacheControlMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) }))))
	for _, tc := range []struct {
		method, path string
		public       bool
	}{
		{http.MethodGet, chartFontStylesheet, true},
		{http.MethodHead, "/static/fonts/noto-sans-sc/noto-sans-sc-119-wght-normal.woff2", true},
		{http.MethodGet, "/static/fonts/noto-sans-sc/LICENSE", true},
		{http.MethodPost, chartFontStylesheet, false},
		{http.MethodGet, "/api/status", false},
		{http.MethodGet, "/static/fonts/noto-sans-sc/../../api/status", false},
		{http.MethodGet, "/static/fonts/noto-sans-sc/manifest.json", false},
		{http.MethodGet, "/static/echarts/echarts.min.js", false},
	} {
		t.Run(tc.method+tc.path, func(t *testing.T) {
			r := httptest.NewRequest(tc.method, "http://127.0.0.1:8080"+tc.path, nil)
			r.Header.Set("Origin", "null")
			w := httptest.NewRecorder()
			next.ServeHTTP(w, r)
			if tc.public {
				if w.Code != http.StatusNoContent || w.Header().Get("Access-Control-Allow-Origin") != "*" {
					t.Fatalf("sandbox cannot read public font: status=%d headers=%v", w.Code, w.Header())
				}
			} else if w.Code != http.StatusForbidden || w.Header().Get("Access-Control-Allow-Origin") != "" {
				t.Fatalf("non-font request escaped local boundary: status=%d headers=%v", w.Code, w.Header())
			}
			if w.Header().Get("Access-Control-Allow-Credentials") != "" || w.Header().Get("Set-Cookie") != "" {
				t.Fatal("public font access must not grant credentials")
			}
		})
	}
	r := httptest.NewRequest(http.MethodGet, "http://evil.invalid"+chartFontStylesheet, nil)
	w := httptest.NewRecorder()
	next.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatal("font exception bypassed local Host validation")
	}
}

func TestChartBundledFontContract(t *testing.T) {
	document := finalizeChartHTML(presentChartHTML([]byte("<html><head></head><body></body></html>"), chartPresentation{Presentation: Presentation{Theme: "light", Locale: "zh-Hans"}}))
	for _, text := range []string{`href="` + chartFontStylesheet + `"`, "Noto Sans SC Variable", "document.fonts.load", "fontFamily:cfg.fontFamily", "font-src 'self' data:"} {
		if !bytes.Contains(document, []byte(text)) {
			t.Fatalf("missing offline chart-font contract: %s", text)
		}
	}
	if bytes.Contains(document, []byte("fonts.googleapis.com")) || bytes.Contains(document, []byte("fonts.gstatic.com")) {
		t.Fatal("chart fonts must not depend on a CDN")
	}
}
