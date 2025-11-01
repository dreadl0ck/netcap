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

import "time"

// FileInfo represents file metadata
type FileInfo struct {
	Name         string  `json:"name"`
	Path         string  `json:"path"`
	Size         int64   `json:"size"`
	ModifiedTime int64   `json:"modifiedTime"`
	IsCompleted  bool    `json:"isCompleted"`
	Error        *string `json:"error,omitempty"`
	BPFFilter    string  `json:"bpfFilter,omitempty"` // BPF filter used during capture
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
