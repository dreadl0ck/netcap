//go:build !appstore

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
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/dreadl0ck/netcap/resolvers"
)

// analysisErrorLogName is the per-run error log filename for the direct
// edition. See the appstore build's copy in server_inprocess.go for why the
// name differs there.
const analysisErrorLogName = "analysis_error.log"

func inProcessResolverConfig() resolvers.Config {
	return resolvers.Config{
		ReverseDNS: false, LocalDNS: false, MACDB: true,
		ServiceDB: true, GeolocationDB: true,
	}
}

func inProcessRequiredExcludes() string { return "" }

// runAnalysis executes a netcap capture analysis out-of-process by shelling
// out to the "net" CLI. This is the direct-edition path; the App Store build
// replaces it with the in-process collector (see server_inprocess.go).
func (s *Server) runAnalysis(job *AnalysisJob) {
	if s.isServiceMode {
		log.Printf("[Service] Starting analysis for session %s", job.SessionID)
	} else {
		log.Printf("[WebUI] Starting analysis for uploaded file: %s", job.InputFile)
	}

	// Update status to processing (service mode only)
	if s.sessionManager != nil {
		s.sessionManager.UpdateSessionStatus(job.SessionID, StatusProcessing, "", "")
	}

	// Enable file extraction - create files directory within the output directory
	// Note: FileStorage must be a RELATIVE path since it gets joined with Out directory
	fileStorageRelPath := "files"
	filesDir := filepath.Join(job.OutputDir, fileStorageRelPath)
	if err := os.MkdirAll(filesDir, 0755); err != nil {
		log.Printf("[Service] Warning: Failed to create files directory: %v", err)
		fileStorageRelPath = "" // Disable file storage if we can't create the directory
	} else {
		log.Printf("[Service] File extraction enabled for session %s: %s", job.SessionID, filesDir)
	}

	// Build netcap capture command
	args := []string{
		"capture",
		"-read", job.InputFile,
		"-out", job.OutputDir,
		"-quiet",
		"-y",        // Force overwrite without prompting (required for non-interactive mode)
		"-http", "", // Disable web UI server
	}

	// Add critical stream processing flags to ensure SSH records are created
	args = append(args,
		"-reassemble-connections=true", // REQUIRED for SSH and all stream-based decoders
		"-writeincomplete=true",        // Write incomplete streams immediately
		"-ignorefsmerr=true",           // Ignore FSM errors for better reliability
		"-allowmissinginit=true",       // Allow streams without handshake
		"-conns",                       // Save raw conversation data to tcp/udp folders (corresponds to SaveConns config)
	)

	// Add file extraction flag if directory was created successfully (use relative path!)
	if fileStorageRelPath != "" {
		args = append(args, "-fileStorage", fileStorageRelPath)
	}

	if job.EnableDPI {
		args = append(args, "-dpi")
	}

	// Add payload capture flag if enabled
	if s.GetPayloadCapture() {
		args = append(args, "-payload")
		log.Printf("[Service] Payload capture enabled for session %s", job.SessionID)
	}

	// Apply BPF filter if set
	if job.BPFFilter != "" {
		args = append(args, "-bpf", job.BPFFilter)
		log.Printf("[Service] Applying BPF filter for session %s: %s", job.SessionID, job.BPFFilter)
	}

	// Apply decoder config if set
	if job.IncludeDecoders != "" {
		args = append(args, "-include", job.IncludeDecoders)
		log.Printf("[Service] Including decoders for session %s: %s", job.SessionID, job.IncludeDecoders)
	}

	// Build exclude decoders list
	excludeDecoders := job.ExcludeDecoders

	// When DPI is disabled or to prevent crashes, exclude DPI-dependent decoders
	// These decoders can cause nil pointer crashes if DPI is not properly initialized
	if !job.EnableDPI {
		dpiDependentDecoders := "DeviceProfile,IPProfile,Connection"
		if excludeDecoders != "" {
			excludeDecoders += "," + dpiDependentDecoders
		} else {
			excludeDecoders = dpiDependentDecoders
		}
		log.Printf("[Service] DPI disabled - excluding DPI-dependent decoders for session %s", job.SessionID)
	}

	if excludeDecoders != "" {
		args = append(args, "-exclude", excludeDecoders)
		log.Printf("[Service] Excluding decoders for session %s: %s", job.SessionID, excludeDecoders)
	}

	// Determine executable for job execution
	// In dev mode, use the current binary; otherwise use the system "net" binary
	var executable string
	if s.devMode {
		// Dev mode: use the current executable (e.g., ./tmp/main when running with air)
		execPath, err := os.Executable()
		if err != nil {
			log.Printf("[Service] Failed to get current executable path: %v, falling back to 'net'", err)
			executable = "net"
		} else {
			executable = execPath
			log.Printf("[Service] Dev mode: using current executable: %s", executable)
		}
	} else {
		// Production mode: use the system "net" binary
		executable = "net"
	}

	// Create error log file for capturing stdout/stderr
	errorLogPath := filepath.Join(job.OutputDir, analysisErrorLogName)
	errorLogFile, err := os.Create(errorLogPath)
	if err != nil {
		log.Printf("[Service] Failed to create error log file: %v", err)
		// Continue without error log file
		errorLogPath = ""
	}

	// Log the exact command being executed for debugging
	log.Printf("[Service] Executing command: %s %s", executable, strings.Join(args, " "))

	// Run the capture command
	cmd := exec.Command(executable, args...)

	// If we have an error log file, capture output there; otherwise use standard output
	if errorLogFile != nil {
		cmd.Stdout = errorLogFile
		cmd.Stderr = errorLogFile
		defer errorLogFile.Close()
	} else {
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
	}

	// Ensure process reference is cleared when done
	defer func() {
		s.currentCmdMutex.Lock()
		s.currentProc = nil
		s.currentCmdMutex.Unlock()
	}()

	// Start the command
	startTime := time.Now()
	err = cmd.Start()
	if err != nil {
		log.Printf("[Service] Failed to start command for session %s: %v", job.SessionID, err)
		if s.sessionManager != nil {
			s.sessionManager.UpdateSessionStatus(job.SessionID, StatusFailed, fmt.Sprintf("Failed to start analysis: %v", err), "")
		} else {
			s.SetFileError(job.InputFile, fmt.Sprintf("Failed to start analysis: %v", err), "")
		}
		return
	}

	// Store the running process for potential cleanup during shutdown
	s.currentCmdMutex.Lock()
	s.currentProc = cmd.Process
	s.currentCmdMutex.Unlock()

	// Wait for command to complete
	err = cmd.Wait()
	duration := time.Since(startTime)

	if err != nil {
		if s.isServiceMode {
			log.Printf("[Service] Analysis failed for session %s: %v (duration: %v)", job.SessionID, err, duration)
		} else {
			log.Printf("[WebUI] Analysis failed for uploaded file %s: %v (duration: %v)", job.InputFile, err, duration)
		}

		// Write additional error context to log file
		if errorLogFile != nil {
			fmt.Fprintf(errorLogFile, "\n\n=== Analysis Error Summary ===\n")
			if s.isServiceMode {
				fmt.Fprintf(errorLogFile, "Session ID: %s\n", job.SessionID)
			}
			fmt.Fprintf(errorLogFile, "Input File: %s\n", job.InputFile)
			fmt.Fprintf(errorLogFile, "Output Directory: %s\n", job.OutputDir)
			fmt.Fprintf(errorLogFile, "Duration: %v\n", duration)
			fmt.Fprintf(errorLogFile, "Error: %v\n", err)
			fmt.Fprintf(errorLogFile, "Command: %s %s\n", executable, strings.Join(args, " "))
			errorLogFile.Close()
		}

		if s.sessionManager != nil {
			log.Printf("[Service] Setting error log path for session %s: %s", job.SessionID, errorLogPath)
			s.sessionManager.UpdateSessionStatus(job.SessionID, StatusFailed, fmt.Sprintf("Analysis failed: %v", err), errorLogPath)
		} else {
			// Local mode: track error in fileErrors map
			s.SetFileError(job.InputFile, fmt.Sprintf("Analysis failed: %v", err), errorLogPath)
		}
		return
	}

	// Close and remove error log file if analysis succeeded (it would be empty or just normal output)
	if errorLogFile != nil {
		errorLogFile.Close()
		os.Remove(errorLogPath)
	}

	if s.isServiceMode {
		log.Printf("[Service] Analysis completed for session %s (duration: %v)", job.SessionID, duration)
	} else {
		log.Printf("[WebUI] Analysis completed for uploaded file %s (duration: %v)", job.InputFile, duration)
	}

	// List audit record files created
	files, err := os.ReadDir(job.OutputDir)
	if err == nil {
		log.Printf("[Service] Files created in %s:", job.OutputDir)
		for _, file := range files {
			if strings.HasSuffix(file.Name(), ".ncap") || strings.HasSuffix(file.Name(), ".ncap.gz") {
				info, _ := file.Info()
				log.Printf("[Service]   - %s (size: %d bytes)", file.Name(), info.Size())
			}
		}
	}

	// Count and log extracted files
	fileCount := s.countExtractedFiles(filesDir)
	if fileCount > 0 {
		if s.isServiceMode {
			log.Printf("[Service] Extracted %d file(s) for session %s", fileCount, job.SessionID)
		} else {
			log.Printf("[WebUI] Extracted %d file(s) from %s", fileCount, job.InputFile)
		}
	}

	if s.sessionManager != nil {
		s.sessionManager.UpdateSessionStatus(job.SessionID, StatusCompleted, "", "")
		// Store the processing time
		s.sessionManager.UpdateSessionProcessingTime(job.SessionID, duration.Seconds())

		// Auto-select this file if no active file is currently set (service mode only)
		// This makes the first completed capture immediately available for viewing
		s.mu.Lock()
		if s.activeInputFile == "" {
			// Get session info to set as active
			if session, ok := s.sessionManager.GetSession(job.SessionID); ok {
				s.currentSession = job.SessionID
				s.outDir = job.OutputDir
				s.activeInputFile = session.InputFile
				log.Printf("[Service] Auto-selected first completed capture: session=%s, file=%s",
					job.SessionID, session.InputFilename)
			}
		}
		s.mu.Unlock()
	} else {
		// Local mode: track completion
		s.MarkFileCompleted(job.InputFile)
		s.SetFileProcessingTime(job.InputFile, duration.Seconds())
		s.SetFileOutputDir(job.InputFile, job.OutputDir)
		s.SetFileBPFFilter(job.InputFile, job.BPFFilter)
	}

	// Execute rules automatically after successful analysis (async to not block next job)
	go s.executeRulesForJob(job)
}
