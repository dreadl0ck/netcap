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

package try

import (
	"os"
	"path/filepath"

	"github.com/namsral/flag"
)

// getDefaultDataDir returns the default data directory based on environment
func getDefaultDataDir() string {
	// Check if running in container (common indicator)
	if _, err := os.Stat("/.dockerenv"); err == nil {
		return "/data/netcap-try"
	}

	// For local development, use a directory in user's home
	homeDir, err := os.UserHomeDir()
	if err != nil {
		// Fallback to current directory
		return "./netcap-try-data"
	}

	return filepath.Join(homeDir, ".local", "share", "netcap-try")
}

var (
	fs                 = flag.NewFlagSetWithEnvPrefix(os.Args[0], "NC", flag.ExitOnError)
	flagGenerateConfig = fs.Bool("gen-config", false, "generate config")
	_                  = fs.String("config", "", "read configuration from file at path")

	// Server configuration
	flagHTTP    = fs.String("http", "localhost:7070", "HTTP server address (e.g., localhost:7070)")
	flagDataDir = fs.String("data-dir", getDefaultDataDir(), "directory for uploads and results")
	flagDPI     = fs.Bool("dpi", true, "enable DPI (Deep Packet Inspection) for all analyses")

	// Rate limiting and cleanup
	flagMaxFileSize     = fs.Int64("max-file-size", 50*1024*1024, "maximum upload file size in bytes (default: 50MB)")
	flagMaxAnalysisHour = fs.Int("max-analysis-hour", 2, "maximum number of analyses per IP per hour")
	flagSessionExpiry   = fs.Int("session-expiry", 60, "session expiry time in minutes")
	flagCleanupInterval = fs.Int("cleanup-interval", 10, "cleanup check interval in minutes")
	flagMaxStorageBytes = fs.Int64("max-storage", 10*1024*1024*1024, "maximum total storage for uploads and results in bytes (default: 10GB, 0 = unlimited)")
)
