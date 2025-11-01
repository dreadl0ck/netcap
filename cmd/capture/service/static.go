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

package service

import (
	"io/fs"
	"log"
	"net/http"

	"github.com/dreadl0ck/netcap/cmd/capture/webui"
)

// handleStatic serves static frontend assets from the shared webui package
func (s *Server) handleStatic() http.Handler {
	// Import and use the webui embed
	fsSub, err := fs.Sub(webui.EmbeddedAssets, "frontend/out")
	if err != nil {
		// Fallback to serving a simple message if assets aren't built
		log.Printf("[Service] Warning: Failed to load embedded assets: %v", err)
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			w.Write([]byte(`
				<!DOCTYPE html>
				<html>
				<head><title>Netcap Service Mode</title></head>
				<body>
					<h1>Netcap Service Mode</h1>
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
