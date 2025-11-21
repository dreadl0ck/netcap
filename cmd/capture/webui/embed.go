/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) 2017-2020 Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

package webui

import (
	"embed"
	"io/fs"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Embed the frontend assets
//
//go:embed frontend/out
//go:embed frontend/out/_next
//go:embed frontend/out/_next/static
//go:embed frontend/out/_next/static/chunks
//go:embed frontend/out/_next/static/chunks/*.js
//go:embed frontend/out/_next/static/*/*.js
//go:embed frontend/out/_next/static/*/*.json
//go:embed frontend/out/*.html
//go:embed frontend/out/*/*.html
//go:embed all:frontend/out/static
var EmbeddedAssets embed.FS

// responseWriterWrapper wraps http.ResponseWriter to intercept WriteHeader
type responseWriterWrapper struct {
	http.ResponseWriter
	path       string
	statusCode int
}

func (w *responseWriterWrapper) WriteHeader(statusCode int) {
	w.statusCode = statusCode

	// Force correct Content-Type for JavaScript and CSS files
	if strings.HasSuffix(w.path, ".js") {
		w.ResponseWriter.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	} else if strings.HasSuffix(w.path, ".css") {
		w.ResponseWriter.Header().Set("Content-Type", "text/css; charset=utf-8")
	}

	w.ResponseWriter.WriteHeader(statusCode)
}

// cacheControlMiddleware adds appropriate cache headers for static assets
func cacheControlMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path

		// Wrap the response writer to ensure correct Content-Type
		wrappedWriter := &responseWriterWrapper{
			ResponseWriter: w,
			path:           path,
			statusCode:     200,
		}

		// Determine cache duration based on file type
		var cacheControl string

		// Immutable assets with content hashes (Next.js chunks) - cache for 1 year
		if strings.Contains(path, "/_next/static/") ||
			strings.Contains(path, "/_next/static/chunks/") {
			// These files have content hashes in their names and never change
			cacheControl = "public, max-age=31536000, immutable"
		} else if strings.HasSuffix(path, ".js") ||
			strings.HasSuffix(path, ".css") ||
			strings.HasSuffix(path, ".woff") ||
			strings.HasSuffix(path, ".woff2") ||
			strings.HasSuffix(path, ".ttf") ||
			strings.HasSuffix(path, ".eot") {
			// Other static assets - cache for 1 week
			cacheControl = "public, max-age=604800"
		} else if strings.HasSuffix(path, ".png") ||
			strings.HasSuffix(path, ".jpg") ||
			strings.HasSuffix(path, ".jpeg") ||
			strings.HasSuffix(path, ".gif") ||
			strings.HasSuffix(path, ".svg") ||
			strings.HasSuffix(path, ".ico") ||
			strings.HasSuffix(path, ".webp") {
			// Images - cache for 1 week
			cacheControl = "public, max-age=604800"
		} else if strings.HasSuffix(path, ".html") || path == "/" {
			// HTML pages - cache for 1 hour with revalidation
			cacheControl = "public, max-age=3600, must-revalidate"
		} else {
			// Everything else - cache for 1 hour
			cacheControl = "public, max-age=3600"
		}

		w.Header().Set("Cache-Control", cacheControl)

		// Add Expires header for backwards compatibility (1 week from now for static assets)
		if strings.Contains(cacheControl, "immutable") {
			expires := time.Now().Add(365 * 24 * time.Hour)
			w.Header().Set("Expires", expires.UTC().Format(http.TimeFormat))
		} else if strings.Contains(cacheControl, "604800") {
			expires := time.Now().Add(7 * 24 * time.Hour)
			w.Header().Set("Expires", expires.UTC().Format(http.TimeFormat))
		}

		next.ServeHTTP(wrappedWriter, r)
	})
}

// handleStatic serves static frontend assets
func (s *Server) handleStatic() http.Handler {
	// If custom assets path is specified (dev mode), serve from filesystem
	if s.assetsPath != "" {
		absPath, err := filepath.Abs(s.assetsPath)
		if err == nil {
			if _, err := os.Stat(absPath); err == nil {
				log.Printf("[WebUI] Serving assets from filesystem: %s", absPath)
				return cacheControlMiddleware(http.FileServer(http.Dir(absPath)))
			}
		}
		log.Printf("[WebUI] Warning: Custom assets path not accessible: %s", s.assetsPath)
	}

	// Otherwise, serve embedded assets
	fsSub, err := fs.Sub(EmbeddedAssets, "frontend/out")
	if err != nil {
		// Fallback to serving a simple message if assets aren't built
		log.Printf("[WebUI] Warning: Failed to load embedded assets: %v", err)
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			w.Write([]byte(`
				<!DOCTYPE html>
				<html>
				<head><title>Netcap Web UI</title></head>
				<body>
					<h1>Netcap Web UI</h1>
					<p>Frontend assets not built. Build the frontend with:</p>
					<pre>cd cmd/capture/webui/frontend && npm install && npm run build</pre>
					<p>API endpoints are available at <a href="/api/status">/api/status</a></p>
				</body>
				</html>
			`))
		})
	}

	log.Printf("[WebUI] Serving embedded assets from frontend/out")

	return cacheControlMiddleware(http.FileServer(http.FS(fsSub)))
}
