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

import "time"

// FileInfo represents file metadata
type FileInfo struct {
	ID               string  `json:"id"` // Unique identifier for the file (used for API calls)
	Name             string  `json:"name"`
	Path             string  `json:"path"`
	Size             int64   `json:"size"`
	ModifiedTime     int64   `json:"modifiedTime"`
	IsCompleted      bool    `json:"isCompleted"`
	Error            *string `json:"error,omitempty"`
	ErrorLogPath     *string `json:"errorLogPath,omitempty"`   // Path to detailed error log file
	BPFFilter        string  `json:"bpfFilter,omitempty"`      // BPF filter used during capture
	ProcessingTime   float64 `json:"processingTime,omitempty"` // Processing duration in seconds
	Hash             string  `json:"hash,omitempty"`           // SHA256 hash of the file
	HasReportedIssue bool    `json:"hasReportedIssue"`         // Whether an issue report has been submitted for this file
	SessionID        string  `json:"sessionId,omitempty"`      // Session ID (service mode only)
}

// AuditFileInfo extends FileInfo with audit record specific metadata
type AuditFileInfo struct {
	FileInfo
	Type        string `json:"type"`
	RecordCount int64  `json:"recordCount,omitempty"`
	Layer       string `json:"layer"`
}

// StatusResponse represents the capture status
type StatusResponse struct {
	IsProcessing    bool      `json:"isProcessing"`
	OutputDir       string    `json:"outputDir"`
	InputFiles      []string  `json:"inputFiles"`
	ServerStarted   time.Time `json:"serverStarted"`
	ActiveInputFile string    `json:"activeInputFile"`
	IsMultiFile     bool      `json:"isMultiFile"`
	IsServiceMode   bool      `json:"isServiceMode,omitempty"`
	IsLiveMode      bool      `json:"isLiveMode"`
	SessionID       string    `json:"sessionId,omitempty"`   // Current session ID (service mode only)
	LogoSubText     string    `json:"logoSubText,omitempty"` // Custom label shown below NETCAP logo
}

// AuditStatsResponse represents the audit record statistics response
type AuditStatsResponse struct {
	TotalRecords       int64 `json:"totalRecords"`
	ExploitCount       int64 `json:"exploitCount"`
	VulnerabilityCount int64 `json:"vulnerabilityCount"`
	CredentialsCount   int64 `json:"credentialsCount"`
	SoftwareCount      int64 `json:"softwareCount"`
}

// LayerType represents the encapsulation layer of a protocol
type LayerType int

const (
	LayerLink LayerType = iota
	LayerNetwork
	LayerTransport
	LayerApplication
	LayerStream
	LayerAbstract
	LayerUnknown
)

// UserDPIPreferences represents user-specific DPI module preferences
type UserDPIPreferences struct {
	EnabledModules []string  `json:"enabledModules"`
	LastUpdated    time.Time `json:"lastUpdated"`
}

// AnalysisJob represents a job in the analysis queue (service mode only)
type AnalysisJob struct {
	SessionID       string
	InputFile       string
	OutputDir       string
	EnableDPI       bool
	BPFFilter       string // BPF filter to apply during capture
	IncludeDecoders string // Decoders to include
	ExcludeDecoders string // Decoders to exclude
}
