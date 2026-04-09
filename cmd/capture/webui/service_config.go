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
	"os"
	"path/filepath"
)

// ServiceConfig holds the service mode configuration
type ServiceConfig struct {
	DataDir               string
	MaxFileSize           int64
	MaxAnalysisHour       int
	SessionExpiry         int
	CleanupInterval       int
	MaxStorageBytes       int64
	MaxIssueReportsPerDay int  // Maximum number of issue reports per IP per day
	PreloadLargestN       int  // Load only the N largest files from pcaps folder (0 = all files)
	EnforceMaxSizePreload bool // Enforce service max file size for preloaded pcaps
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
		EnforceMaxSizePreload: true,                    // enforce max size by default for preloaded pcaps
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
