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
	"os"
	"path/filepath"
)

// ServiceConfig holds the service mode configuration
type ServiceConfig struct {
	DataDir                   string
	MaxFileSize               int64
	MaxAnalysisHour           int
	SessionExpiry             int
	CleanupInterval           int
	MaxStorageBytes           int64
	MaxIssueReportsPerDay     int  // Maximum number of issue reports per IP per day
	PreloadLargestN           int  // Load only the N largest files from pcaps folder (0 = all files)
	EnforceMaxSizePreload     bool // Enforce service max file size for preloaded pcaps
}

// DefaultServiceConfig returns the default service configuration
func DefaultServiceConfig() *ServiceConfig {
	return &ServiceConfig{
		DataDir:               getDefaultDataDir(),
		MaxFileSize:           100 * 1024 * 1024, // 100MB
		MaxAnalysisHour:       10,
		SessionExpiry:         60,                      // 60 minutes
		CleanupInterval:       10,                      // 10 minutes
		MaxStorageBytes:       10 * 1024 * 1024 * 1024, // 10GB
		MaxIssueReportsPerDay: 5,                       // 5 issue reports per IP per day
		PreloadLargestN:       0,                       // 0 = load all files
		EnforceMaxSizePreload: false,                   // Don't enforce max size by default for preloaded pcaps
	}
}

// getDefaultDataDir returns the default data directory based on environment
func getDefaultDataDir() string {
	// Check if running in container (common indicator)
	if _, err := os.Stat("/.dockerenv"); err == nil {
		return "/data/netcap-service"
	}

	// For local development, use a directory in user's home
	homeDir, err := os.UserHomeDir()
	if err != nil {
		// Fallback to current directory
		return "./netcap-service-data"
	}

	return filepath.Join(homeDir, ".local", "share", "netcap-service")
}

