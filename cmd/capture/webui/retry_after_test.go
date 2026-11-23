package webui

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRetryAfterMiddlewareMarksBusyResponses(t *testing.T) {
	for _, tc := range []struct {
		status int
		preset string
		want   string
	}{
		{http.StatusTooManyRequests, "", "1"},
		{http.StatusServiceUnavailable, "", "1"},
		{http.StatusTooManyRequests, "7", "7"},
		{http.StatusRequestEntityTooLarge, "", ""},
		{http.StatusInsufficientStorage, "", ""},
		{http.StatusOK, "", ""},
	} {
		w := httptest.NewRecorder()
		retryAfterMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if tc.preset != "" {
				w.Header().Set("Retry-After", tc.preset)
			}
			http.Error(w, "x", tc.status)
		})).ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/alerts", nil))
		if got := w.Header().Get("Retry-After"); got != tc.want || w.Code != tc.status {
			t.Errorf("%d: Retry-After %q, want %q", tc.status, got, tc.want)
		}
	}
	var flushed bool
	retryAfterMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, flushed = w.(http.Flusher)
	})).ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/api/alerts/stream", nil))
	if !flushed {
		t.Fatal("streaming handlers lost http.Flusher")
	}
}
