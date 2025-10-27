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
	"io"
	"io/fs"
	"log"
	"net/http"
	"sync"
	"time"
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

// Server wraps the try service for webUI access
type Server struct {
	tryServer interface{} // Reference to try.Server
	mu        sync.RWMutex
}

// NewServer creates a new webUI server wrapper
func NewServer(tryServer interface{}) *Server {
	return &Server{
		tryServer: tryServer,
	}
}

// HandleStatic serves either the upload page or the webUI based on session state
func (s *Server) HandleStatic(getCurrentSession func() interface{}) http.Handler {
	// Try to load embedded assets from the capture webUI (via symlink)
	fsSub, err := fs.Sub(embeddedAssets, "frontend/out")
	if err != nil {
		log.Printf("[WebUI] Warning: Failed to load embedded assets: %v", err)
		log.Printf("[WebUI] Will serve upload page for all requests")
	} else {
		log.Printf("[WebUI] Successfully loaded embedded assets")
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("[WebUI] Request: %s %s", r.Method, r.URL.Path)

		if err == nil {
			// Strip leading slash from path
			path := r.URL.Path
			if len(path) > 0 && path[0] == '/' {
				path = path[1:]
			}

			// Strip trailing slash (unless it's the root)
			if len(path) > 0 && path[len(path)-1] == '/' {
				path = path[:len(path)-1]
			}

			// For empty path, serve index.html
			if path == "" {
				path = "index.html"
			}

			log.Printf("[WebUI] Attempting to serve file: %s", path)

			// Try to open the file directly
			file, fileErr := fsSub.Open(path)
			if fileErr == nil {
				defer file.Close()

				// Check if it's a directory
				stat, statErr := file.Stat()
				if statErr == nil && stat.IsDir() {
					// It's a directory, try index.html inside it
					file.Close() // Close the directory
					indexPath := path + "/index.html"
					log.Printf("[WebUI] Path is directory, trying: %s", indexPath)
					indexFile, indexErr := fsSub.Open(indexPath)
					if indexErr == nil {
						defer indexFile.Close()
						http.ServeContent(w, r, indexPath, GetServerStartTime(), indexFile.(io.ReadSeeker))
						return
					}
				} else {
					// It's a file, serve it
					http.ServeContent(w, r, path, GetServerStartTime(), file.(io.ReadSeeker))
					return
				}
			}

			// If direct file not found, try path/index.html (for Next.js static routes)
			indexPath := path + "/index.html"
			log.Printf("[WebUI] File not found, trying: %s", indexPath)
			indexFile, indexErr := fsSub.Open(indexPath)
			if indexErr == nil {
				defer indexFile.Close()
				http.ServeContent(w, r, indexPath, GetServerStartTime(), indexFile.(io.ReadSeeker))
				return
			}

			log.Printf("[WebUI] File not found in embedded assets: %s", path)
		}

		// File not found
		log.Printf("[WebUI] Returning 404 for: %s", r.URL.Path)
		http.NotFound(w, r)
	})
}

var serverStartTime = time.Now()

// GetServerStartTime returns when the server started
func GetServerStartTime() time.Time {
	return serverStartTime
}
