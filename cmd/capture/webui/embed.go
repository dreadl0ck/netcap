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
	"net/http"
	"os"
	"path/filepath"
)

//go:embed frontend/out
//go:embed frontend/out/_next
//go:embed frontend/out/_next/static
//go:embed frontend/out/_next/static/chunks
//go:embed frontend/out/_next/static/chunks/pages
//go:embed frontend/out/_next/static/chunks/*.js
//go:embed frontend/out/_next/static/chunks/pages/*.js
//go:embed frontend/out/_next/static/*/*.js
//go:embed frontend/out/*.html
//go:embed frontend/out/*/*.html
var embeddedAssets embed.FS

// handleStatic serves static frontend assets
func (s *Server) handleStatic() http.Handler {
	// If custom assets path is specified (dev mode), serve from filesystem
	if s.assetsPath != "" {
		absPath, err := filepath.Abs(s.assetsPath)
		if err == nil {
			if _, err := os.Stat(absPath); err == nil {
				return http.FileServer(http.Dir(absPath))
			}
		}
	}

	// Otherwise, serve embedded assets
	fsSub, err := fs.Sub(embeddedAssets, "frontend/out")
	if err != nil {
		// Fallback to serving a simple message if assets aren't built
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

	return http.FileServer(http.FS(fsSub))
}
