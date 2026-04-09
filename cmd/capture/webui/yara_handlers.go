/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 */

package webui

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/dreadl0ck/netcap/decoder/stream/file"
)

// YaraRuleInfo represents metadata about a YARA rule file.
type YaraRuleInfo struct {
	Name        string `json:"name"`
	Filename    string `json:"filename"`
	Size        int64  `json:"size"`
	Enabled     bool   `json:"enabled"`
	ModifiedAt  int64  `json:"modifiedAt"`
	RuleCount   int    `json:"ruleCount"`
	Description string `json:"description"`
}

// YaraScanResult represents a YARA scan result for a single file.
type YaraScanResult struct {
	FilePath   string   `json:"filePath"`
	FileName   string   `json:"fileName"`
	Matches    []string `json:"matches"`
	ScanTimeMs int64    `json:"scanTimeMs"`
}

// YaraScanResponse represents the response from a YARA scan operation.
type YaraScanResponse struct {
	Results      []YaraScanResult `json:"results"`
	TotalFiles   int              `json:"totalFiles"`
	FilesScanned int              `json:"filesScanned"`
	TotalMatches int              `json:"totalMatches"`
	ScanTimeMs   int64            `json:"scanTimeMs"`
}

// YaraStatusResponse represents the YARA subsystem status.
type YaraStatusResponse struct {
	Available    bool   `json:"available"`
	RulesDir     string `json:"rulesDir"`
	EnabledRules int    `json:"enabledRules"`
	TotalRules   int    `json:"totalRules"`
}

// yaraRulesMeta tracks enabled/disabled state for each rule file.
type yaraRulesMeta struct {
	mu   sync.RWMutex
	file string
	data map[string]bool // filename -> enabled
}

func newYaraRulesMeta(metaFile string) *yaraRulesMeta {
	m := &yaraRulesMeta{
		file: metaFile,
		data: make(map[string]bool),
	}
	m.load()
	return m
}

func (m *yaraRulesMeta) load() {
	data, err := os.ReadFile(m.file)
	if err != nil {
		return
	}
	json.Unmarshal(data, &m.data)
}

func (m *yaraRulesMeta) save() error {
	m.mu.RLock()
	defer m.mu.RUnlock()
	data, err := json.MarshalIndent(m.data, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(m.file, data, 0644)
}

func (m *yaraRulesMeta) isEnabled(filename string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	enabled, ok := m.data[filename]
	if !ok {
		return true // enabled by default
	}
	return enabled
}

func (m *yaraRulesMeta) setEnabled(filename string, enabled bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.data[filename] = enabled
}

func (m *yaraRulesMeta) remove(filename string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.data, filename)
}

// getYaraRulesDir returns the path to the YARA rules storage directory.
func getYaraRulesDir() string {
	return filepath.Join(getConfigRootPath(), "yara-rules")
}

// ensureYaraRulesDir creates the YARA rules directory if it doesn't exist.
func ensureYaraRulesDir() (string, error) {
	dir := getYaraRulesDir()
	if err := os.MkdirAll(dir, 0755); err != nil {
		return "", fmt.Errorf("failed to create yara rules directory: %w", err)
	}
	return dir, nil
}

// getOrCreateYaraScanner returns the global YARA scanner, initializing it if needed.
func getOrCreateYaraScanner() *file.YaraScanner {
	scanner := file.GetGlobalYaraScanner()
	if scanner != nil {
		return scanner
	}

	rulesDir := getYaraRulesDir()
	scanner, err := file.InitGlobalYaraScanner(rulesDir)
	if err != nil {
		log.Printf("[YARA] Failed to initialize scanner: %v", err)
		return nil
	}
	return scanner
}

// handleYaraStatus returns the YARA subsystem status.
func (s *Server) handleYaraStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	available := file.YaraAvailable()
	rulesDir := getYaraRulesDir()
	totalRules := 0

	scanner := getOrCreateYaraScanner()
	if scanner != nil {
		totalRules = scanner.RuleCount()
	}

	RespondJSON(w, http.StatusOK, YaraStatusResponse{
		Available:    available,
		RulesDir:     rulesDir,
		EnabledRules: totalRules,
		TotalRules:   totalRules,
	})
}

// handleYaraRules lists all YARA rule files.
func (s *Server) handleYaraRules(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	rulesDir := getYaraRulesDir()
	metaFile := filepath.Join(rulesDir, "yara-rules-meta.json")
	meta := newYaraRulesMeta(metaFile)

	var rules []YaraRuleInfo

	entries, err := os.ReadDir(rulesDir)
	if err != nil {
		if os.IsNotExist(err) {
			RespondJSON(w, http.StatusOK, map[string]any{"rules": []YaraRuleInfo{}})
			return
		}
		RespondJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		ext := strings.ToLower(filepath.Ext(entry.Name()))
		if ext != ".yar" && ext != ".yara" {
			continue
		}

		info, err := entry.Info()
		if err != nil {
			continue
		}

		// Extract description from first comment line
		desc := ""
		ruleCount := 0
		content, err := os.ReadFile(filepath.Join(rulesDir, entry.Name()))
		if err == nil {
			desc, ruleCount = parseYaraFileInfo(string(content))
		}

		rules = append(rules, YaraRuleInfo{
			Name:        strings.TrimSuffix(entry.Name(), ext),
			Filename:    entry.Name(),
			Size:        info.Size(),
			Enabled:     meta.isEnabled(entry.Name()),
			ModifiedAt:  info.ModTime().Unix(),
			RuleCount:   ruleCount,
			Description: desc,
		})
	}

	if rules == nil {
		rules = []YaraRuleInfo{}
	}

	RespondJSON(w, http.StatusOK, map[string]any{"rules": rules})
}

// handleUploadYaraRule handles uploading a new YARA rule file.
func (s *Server) handleUploadYaraRule(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := r.ParseMultipartForm(10 << 20); err != nil { // 10MB max
		RespondJSON(w, http.StatusBadRequest, map[string]any{"error": "Failed to parse form: " + err.Error()})
		return
	}

	f, header, err := r.FormFile("file")
	if err != nil {
		RespondJSON(w, http.StatusBadRequest, map[string]any{"error": "No file provided"})
		return
	}
	defer f.Close()

	// Validate extension
	ext := strings.ToLower(filepath.Ext(header.Filename))
	if ext != ".yar" && ext != ".yara" {
		RespondJSON(w, http.StatusBadRequest, map[string]any{"error": "Only .yar and .yara files are accepted"})
		return
	}

	// Read content
	content, err := io.ReadAll(f)
	if err != nil {
		RespondJSON(w, http.StatusInternalServerError, map[string]any{"error": "Failed to read file: " + err.Error()})
		return
	}

	// Validate YARA syntax by compiling
	if err := file.ValidateYaraSource(string(content)); err != nil {
		RespondJSON(w, http.StatusBadRequest, map[string]any{
			"error":   "YARA compilation error",
			"details": err.Error(),
		})
		return
	}

	// Save the file
	rulesDir, err := ensureYaraRulesDir()
	if err != nil {
		RespondJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}

	// Sanitize filename but preserve extension
	baseName := strings.TrimSuffix(header.Filename, ext)
	safeName := sanitizeYaraFilename(baseName) + ext
	destPath := filepath.Join(rulesDir, safeName)

	if err := os.WriteFile(destPath, content, 0644); err != nil {
		RespondJSON(w, http.StatusInternalServerError, map[string]any{"error": "Failed to save file: " + err.Error()})
		return
	}

	// Enable by default
	metaFile := filepath.Join(rulesDir, "yara-rules-meta.json")
	meta := newYaraRulesMeta(metaFile)
	meta.setEnabled(safeName, true)
	meta.save()

	// Reload scanner
	scanner := getOrCreateYaraScanner()
	if scanner != nil {
		scanner.Reload()
	}

	log.Printf("[YARA] Uploaded rule file: %s", safeName)

	desc, ruleCount := parseYaraFileInfo(string(content))
	RespondJSON(w, http.StatusOK, map[string]any{
		"message":   "Rule uploaded successfully",
		"filename":  safeName,
		"ruleCount": ruleCount,
		"description": desc,
	})
}

// handleYaraRuleByName handles GET for a specific YARA rule file.
func (s *Server) handleYaraRuleByName(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	name := extractPathParam(r.URL.Path, "/api/yara/rules/")
	if name == "" {
		RespondJSON(w, http.StatusBadRequest, map[string]any{"error": "Rule name required"})
		return
	}

	rulesDir := getYaraRulesDir()
	filePath := filepath.Join(rulesDir, name)

	// Prevent path traversal
	if !strings.HasPrefix(filepath.Clean(filePath), filepath.Clean(rulesDir)) {
		RespondJSON(w, http.StatusBadRequest, map[string]any{"error": "Invalid rule name"})
		return
	}

	content, err := os.ReadFile(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			RespondJSON(w, http.StatusNotFound, map[string]any{"error": "Rule not found"})
			return
		}
		RespondJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}

	RespondJSON(w, http.StatusOK, map[string]any{
		"name":     strings.TrimSuffix(name, filepath.Ext(name)),
		"filename": name,
		"content":  string(content),
	})
}

// handleUpdateYaraRule handles PUT to update a YARA rule file's content or enabled state.
func (s *Server) handleUpdateYaraRule(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	name := extractPathParam(r.URL.Path, "/api/yara/rules/")
	if name == "" {
		RespondJSON(w, http.StatusBadRequest, map[string]any{"error": "Rule name required"})
		return
	}

	rulesDir := getYaraRulesDir()
	filePath := filepath.Join(rulesDir, name)

	if !strings.HasPrefix(filepath.Clean(filePath), filepath.Clean(rulesDir)) {
		RespondJSON(w, http.StatusBadRequest, map[string]any{"error": "Invalid rule name"})
		return
	}

	var req struct {
		Content *string `json:"content"`
		Enabled *bool   `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		RespondJSON(w, http.StatusBadRequest, map[string]any{"error": "Invalid request body"})
		return
	}

	// Update content if provided
	if req.Content != nil {
		// Validate
		if err := file.ValidateYaraSource(*req.Content); err != nil {
			RespondJSON(w, http.StatusBadRequest, map[string]any{
				"error":   "YARA compilation error",
				"details": err.Error(),
			})
			return
		}

		if err := os.WriteFile(filePath, []byte(*req.Content), 0644); err != nil {
			RespondJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
			return
		}

		// Reload scanner
		scanner := getOrCreateYaraScanner()
		if scanner != nil {
			scanner.Reload()
		}
	}

	// Update enabled state if provided
	if req.Enabled != nil {
		metaFile := filepath.Join(rulesDir, "yara-rules-meta.json")
		meta := newYaraRulesMeta(metaFile)
		meta.setEnabled(name, *req.Enabled)
		meta.save()

		// Reload scanner to pick up enabled/disabled changes
		scanner := getOrCreateYaraScanner()
		if scanner != nil {
			scanner.Reload()
		}
	}

	RespondJSON(w, http.StatusOK, map[string]any{"message": "Rule updated"})
}

// handleDeleteYaraRule handles DELETE for a YARA rule file.
func (s *Server) handleDeleteYaraRule(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	name := extractPathParam(r.URL.Path, "/api/yara/rules/")
	if name == "" {
		RespondJSON(w, http.StatusBadRequest, map[string]any{"error": "Rule name required"})
		return
	}

	rulesDir := getYaraRulesDir()
	filePath := filepath.Join(rulesDir, name)

	if !strings.HasPrefix(filepath.Clean(filePath), filepath.Clean(rulesDir)) {
		RespondJSON(w, http.StatusBadRequest, map[string]any{"error": "Invalid rule name"})
		return
	}

	if err := os.Remove(filePath); err != nil {
		if os.IsNotExist(err) {
			RespondJSON(w, http.StatusNotFound, map[string]any{"error": "Rule not found"})
			return
		}
		RespondJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}

	// Remove from meta
	metaFile := filepath.Join(rulesDir, "yara-rules-meta.json")
	meta := newYaraRulesMeta(metaFile)
	meta.remove(name)
	meta.save()

	// Reload scanner
	scanner := getOrCreateYaraScanner()
	if scanner != nil {
		scanner.Reload()
	}

	log.Printf("[YARA] Deleted rule file: %s", name)
	RespondJSON(w, http.StatusOK, map[string]any{"message": "Rule deleted"})
}

// handleYaraScan scans all extracted files against enabled YARA rules.
func (s *Server) handleYaraScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !file.YaraAvailable() {
		RespondJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "YARA support not compiled in this build"})
		return
	}

	scanner := getOrCreateYaraScanner()
	if scanner == nil || scanner.RuleCount() == 0 {
		RespondJSON(w, http.StatusBadRequest, map[string]any{"error": "No YARA rules loaded"})
		return
	}

	// Determine the files directory
	s.mu.RLock()
	outDir := s.outDir
	if s.isServiceMode && s.currentSession != "" && s.sessionManager != nil {
		if session, ok := s.sessionManager.GetSession(s.currentSession); ok {
			outDir = session.OutputDir
		}
	}
	s.mu.RUnlock()

	filesDir := filepath.Join(outDir, "files")
	if _, err := os.Stat(filesDir); os.IsNotExist(err) {
		RespondJSON(w, http.StatusOK, YaraScanResponse{
			Results: []YaraScanResult{},
		})
		return
	}

	startTime := time.Now()
	var results []YaraScanResult
	totalFiles := 0
	totalMatches := 0

	err := filepath.Walk(filesDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}

		totalFiles++
		fileStart := time.Now()

		matches, err := scanner.ScanFile(path)
		if err != nil {
			log.Printf("[YARA] Error scanning %s: %v", path, err)
			return nil
		}

		scanTimeMs := time.Since(fileStart).Milliseconds()

		if len(matches) > 0 {
			relPath, _ := filepath.Rel(filesDir, path)
			results = append(results, YaraScanResult{
				FilePath:   relPath,
				FileName:   info.Name(),
				Matches:    matches,
				ScanTimeMs: scanTimeMs,
			})
			totalMatches += len(matches)
		}

		return nil
	})

	if err != nil {
		log.Printf("[YARA] Walk error: %v", err)
	}

	if results == nil {
		results = []YaraScanResult{}
	}

	totalScanMs := time.Since(startTime).Milliseconds()
	log.Printf("[YARA] Scan complete: %d files scanned, %d matches in %dms", totalFiles, totalMatches, totalScanMs)

	RespondJSON(w, http.StatusOK, YaraScanResponse{
		Results:      results,
		TotalFiles:   totalFiles,
		FilesScanned: totalFiles,
		TotalMatches: totalMatches,
		ScanTimeMs:   totalScanMs,
	})
}

// handleYaraScanFile scans a single file against YARA rules.
func (s *Server) handleYaraScanFile(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !file.YaraAvailable() {
		RespondJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "YARA support not compiled in this build"})
		return
	}

	scanner := getOrCreateYaraScanner()
	if scanner == nil || scanner.RuleCount() == 0 {
		RespondJSON(w, http.StatusBadRequest, map[string]any{"error": "No YARA rules loaded"})
		return
	}

	var req struct {
		FilePath string `json:"filePath"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.FilePath == "" {
		RespondJSON(w, http.StatusBadRequest, map[string]any{"error": "filePath required"})
		return
	}

	// Determine the files directory
	s.mu.RLock()
	outDir := s.outDir
	if s.isServiceMode && s.currentSession != "" && s.sessionManager != nil {
		if session, ok := s.sessionManager.GetSession(s.currentSession); ok {
			outDir = session.OutputDir
		}
	}
	s.mu.RUnlock()

	filesDir := filepath.Join(outDir, "files")
	fullPath := filepath.Join(filesDir, req.FilePath)

	// Prevent path traversal
	if !strings.HasPrefix(filepath.Clean(fullPath), filepath.Clean(filesDir)) {
		RespondJSON(w, http.StatusBadRequest, map[string]any{"error": "Invalid file path"})
		return
	}

	if _, err := os.Stat(fullPath); os.IsNotExist(err) {
		RespondJSON(w, http.StatusNotFound, map[string]any{"error": "File not found"})
		return
	}

	startTime := time.Now()
	matches, err := scanner.ScanFile(fullPath)
	scanTimeMs := time.Since(startTime).Milliseconds()

	if err != nil {
		RespondJSON(w, http.StatusInternalServerError, map[string]any{"error": fmt.Sprintf("Scan failed: %v", err)})
		return
	}

	if matches == nil {
		matches = []string{}
	}

	RespondJSON(w, http.StatusOK, YaraScanResult{
		FilePath:   req.FilePath,
		FileName:   filepath.Base(req.FilePath),
		Matches:    matches,
		ScanTimeMs: scanTimeMs,
	})
}

// handleYaraRuleRouter dispatches YARA rule requests by method.
func (s *Server) handleYaraRuleRouter(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.handleYaraRuleByName(w, r)
	case http.MethodPut:
		s.handleUpdateYaraRule(w, r)
	case http.MethodDelete:
		s.handleDeleteYaraRule(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// --- helpers ---

// sanitizeYaraFilename cleans a filename for safe storage.
func sanitizeYaraFilename(name string) string {
	safe := strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.' {
			return r
		}
		return '_'
	}, name)
	if safe == "" {
		safe = "unnamed"
	}
	return safe
}

// extractPathParam extracts the trailing path segment after a prefix.
func extractPathParam(path, prefix string) string {
	if !strings.HasPrefix(path, prefix) {
		return ""
	}
	param := strings.TrimPrefix(path, prefix)
	// URL-decode
	return param
}

// parseYaraFileInfo extracts description (first comment) and rule count from YARA source.
func parseYaraFileInfo(source string) (description string, ruleCount int) {
	lines := strings.Split(source, "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)

		// Extract first comment as description
		if description == "" && (strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "/*")) {
			description = strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(trimmed, "//"), "/*"))
			description = strings.TrimSuffix(description, "*/")
			description = strings.TrimSpace(description)
		}

		// Count rule definitions
		if strings.HasPrefix(trimmed, "rule ") {
			ruleCount++
		}
	}
	return
}
