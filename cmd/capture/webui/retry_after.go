package webui

import "net/http"

// retryAfterMiddleware adds "Retry-After: 1" to every 429 and 503 that does
// not set one. Admission refusals are transient, and clients such as the MCP
// tools turn the header into a retry hint instead of a hard failure.
func retryAfterMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(retryAfterWriter{w}, r)
	})
}

type retryAfterWriter struct{ http.ResponseWriter }

func (w retryAfterWriter) WriteHeader(code int) {
	if (code == http.StatusTooManyRequests || code == http.StatusServiceUnavailable) && w.Header().Get("Retry-After") == "" {
		w.Header().Set("Retry-After", "1")
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w retryAfterWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (w retryAfterWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }
