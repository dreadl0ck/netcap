/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
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

// Embed the frontend assets (Vite build output in frontend/dist/).
// The "all:" prefix includes dotfiles. The frontend must be built before compiling.
//
//go:embed all:frontend/dist
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

		// Immutable assets with content hashes (Vite hashed chunks) - cache for 1 year
		if strings.HasPrefix(path, "/assets/") {
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

// spaFallbackHandler wraps an http.FileServer with SPA fallback logic.
// For paths that don't match a static file (no file extension) and aren't API routes,
// it serves index.html so React Router can handle client-side routing.
func spaFallbackHandler(fileServer http.Handler, fsys fs.FS) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path

		// If the path has a file extension or is the root, serve directly
		if path == "/" || strings.Contains(path, ".") {
			fileServer.ServeHTTP(w, r)
			return
		}

		// For paths without extensions (SPA routes like /alerts, /hosts, etc.),
		// serve index.html so React Router handles routing
		r.URL.Path = "/"
		fileServer.ServeHTTP(w, r)
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
				fileServer := http.FileServer(http.Dir(absPath))
				return cacheControlMiddleware(spaFallbackHandler(fileServer, os.DirFS(absPath)))
			}
		}
		log.Printf("[WebUI] Warning: Custom assets path not accessible: %s", s.assetsPath)
	}

	// Otherwise, serve embedded assets
	fsSub, err := fs.Sub(EmbeddedAssets, "frontend/dist")
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
					<pre>cd cmd/capture/webui/frontend && pnpm install && pnpm build</pre>
					<p>API endpoints are available at <a href="/api/status">/api/status</a></p>
				</body>
				</html>
			`))
		})
	}

	log.Printf("[WebUI] Serving embedded assets from frontend/dist")

	fileServer := http.FileServer(http.FS(fsSub))
	return cacheControlMiddleware(spaFallbackHandler(fileServer, fsSub))
}
