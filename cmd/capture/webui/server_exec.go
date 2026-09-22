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

	"github.com/dreadl0ck/netcap/internal/dbs"
	"github.com/dreadl0ck/netcap/internal/resolvers"
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

	// Disable every enrichment whose database is absent.
	//
	// Without this the helper inherits -geoDB=true, the geolocation resolver
	// cannot find GeoLite2-City.mmdb, and the run aborts before the first
	// packet. No installer on any platform ships these databases, so that was
	// every capture on every clean install, reported to the GUI as nothing
	// more than "exit status 1". Analysis now proceeds with reduced
	// enrichment while the UI offers the download.
	if disableFlags := dbs.DisableFlagsForMissingDBs(); len(disableFlags) > 0 {
		args = append(args, disableFlags...)
		log.Printf("[Service] Missing databases, disabling enrichment for session %s: %s",
			job.SessionID, strings.Join(disableFlags, " "))
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
	// In dev mode, use the current binary; otherwise locate the bundled helper
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
		executable = resolveHelperExecutable()
		if executable == "" {
			// Say which binary is missing. Falling through to exec.Command("net")
			// here would run Windows' own net.exe or Samba's, and report the
			// resulting usage error as a netcap failure.
			msg := fmt.Sprintf(
				"capture helper %q not found next to the application or on PATH; reinstall Netcap Pro",
				helperName())
			log.Printf("[Service] %s", msg)
			s.recordAnalysisFailure(job, msg, "")

			return
		}

		log.Printf("[Service] Using capture helper: %s", executable)
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
		s.recordAnalysisFailure(job, fmt.Sprintf("Failed to start analysis: %v", err), "")

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

		// Put the helper's own last words in the summary line. "Analysis
		// failed: exit status 1" is true and tells nobody anything, and it
		// was all the UI ever showed.
		s.recordAnalysisFailure(job, summariseAnalysisFailure(err, errorLogPath), errorLogPath)

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

// recordAnalysisFailure records a failed run against whichever bookkeeping the
// current mode uses. Both modes always get the error log path, so the UI can
// offer the full output in local mode too; it used to be passed only in
// service mode, which is why the desktop app could never show one.
func (s *Server) recordAnalysisFailure(job *AnalysisJob, message, errorLogPath string) {
	if s.sessionManager != nil {
		log.Printf("[Service] Setting error log path for session %s: %s", job.SessionID, errorLogPath)
		s.sessionManager.UpdateSessionStatus(job.SessionID, StatusFailed, message, errorLogPath)

		return
	}

	s.SetFileError(job.InputFile, message, errorLogPath)
}

// analysisErrorSummaryLimit is how many trailing bytes of the helper's output
// are scanned for a usable summary line.
const analysisErrorSummaryLimit = 8192

// summariseAnalysisFailure builds a one-line failure message that names the
// cause rather than the exit code.
func summariseAnalysisFailure(runErr error, errorLogPath string) string {
	base := fmt.Sprintf("Analysis failed: %v", runErr)

	detail := lastMeaningfulLogLine(errorLogPath)
	if detail == "" {
		return base
	}

	return base + " — " + detail
}

// lastMeaningfulLogLine returns the final substantive line of the helper's
// output, skipping blanks and the summary block this file appends.
func lastMeaningfulLogLine(errorLogPath string) string {
	if errorLogPath == "" {
		return ""
	}

	data, err := os.ReadFile(errorLogPath)
	if err != nil {
		return ""
	}

	if len(data) > analysisErrorSummaryLimit {
		data = data[len(data)-analysisErrorSummaryLimit:]
	}

	lines := strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n")

	for i := len(lines) - 1; i >= 0; i-- {
		line := strings.TrimSpace(lines[i])
		if line == "" || isErrorSummaryLine(line) {
			continue
		}

		// Truncate by rune, not by byte: a path or a decoder message can
		// carry non-ASCII, and cutting mid-rune emits U+FFFD into the UI.
		const maxDetail = 300
		if runes := []rune(line); len(runes) > maxDetail {
			line = string(runes[:maxDetail]) + "…"
		}

		return line
	}

	return ""
}

// errorSummaryPrefixes are the labels written by the summary block above. They
// restate what the caller already knows, so they are skipped when looking for
// the helper's own message.
var errorSummaryPrefixes = []string{
	"=== Analysis Error Summary ===",
	"Session ID:",
	"Input File:",
	"Output Directory:",
	"Duration:",
	"Error:",
	"Command:",
}

func isErrorSummaryLine(line string) bool {
	for _, prefix := range errorSummaryPrefixes {
		if strings.HasPrefix(line, prefix) {
			return true
		}
	}

	return false
}
