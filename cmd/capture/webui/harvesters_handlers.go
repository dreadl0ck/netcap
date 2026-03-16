package webui

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/dreadl0ck/netcap/decoder/stream/credentials"
)

// handleHarvestersConfig handles GET and POST requests for harvester configuration
func (s *Server) handleHarvestersConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.getHarvestersConfig(w, r)
	case http.MethodPost:
		s.saveHarvestersConfig(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// getHarvestersConfig returns the current harvester configuration
func (s *Server) getHarvestersConfig(w http.ResponseWriter, r *http.Request) {
	config := credentials.GetHarvesterConfig()

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(config); err != nil {
		http.Error(w, fmt.Sprintf("Failed to encode response: %v", err), http.StatusInternalServerError)
	}
}

// saveHarvestersConfig saves the harvester configuration
func (s *Server) saveHarvestersConfig(w http.ResponseWriter, r *http.Request) {
	var config credentials.HarvestersConfigFile
	if err := json.NewDecoder(r.Body).Decode(&config); err != nil {
		http.Error(w, fmt.Sprintf("Invalid request: %v", err), http.StatusBadRequest)
		return
	}

	// Save to the active config path
	configPath := s.getHarvestersConfigPath()

	// Ensure directory exists
	if err := os.MkdirAll(filepath.Dir(configPath), 0755); err != nil {
		http.Error(w, fmt.Sprintf("Failed to create config directory: %v", err), http.StatusInternalServerError)
		return
	}

	if err := credentials.SaveHarvestersConfig(configPath, &config); err != nil {
		http.Error(w, fmt.Sprintf("Failed to save configuration: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"success": true,
		"message": "Harvester configuration saved successfully. Restart capture to apply changes.",
	})
}

// handleHarvestersPresets lists all saved harvester configuration presets
func (s *Server) handleHarvestersPresets(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	presetsDir := s.getHarvestersPresetsDir()

	// Ensure directory exists
	if err := os.MkdirAll(presetsDir, 0755); err != nil {
		http.Error(w, fmt.Sprintf("Failed to create presets directory: %v", err), http.StatusInternalServerError)
		return
	}

	entries, err := os.ReadDir(presetsDir)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to read presets directory: %v", err), http.StatusInternalServerError)
		return
	}

	presets := make([]HarvesterPresetInfo, 0)
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".yml") && !strings.HasSuffix(entry.Name(), ".yaml") {
			continue
		}

		info, err := entry.Info()
		if err != nil {
			continue
		}

		presetPath := filepath.Join(presetsDir, entry.Name())
		config, err := credentials.LoadHarvestersConfig(presetPath)
		if err != nil {
			continue
		}

		name := strings.TrimSuffix(entry.Name(), filepath.Ext(entry.Name()))

		presets = append(presets, HarvesterPresetInfo{
			Name:           name,
			Description:    fmt.Sprintf("%d harvesters configured", len(config.Harvesters)),
			CreatedAt:      info.ModTime(),
			ModifiedAt:     info.ModTime(),
			HarvesterCount: len(config.Harvesters),
		})
	}

	response := HarvesterPresetListResponse{
		Presets: presets,
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		http.Error(w, fmt.Sprintf("Failed to encode response: %v", err), http.StatusInternalServerError)
	}
}

// handleSaveHarvesterPreset saves a new harvester configuration preset
func (s *Server) handleSaveHarvesterPreset(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var request struct {
		Name   string                           `json:"name"`
		Config credentials.HarvestersConfigFile `json:"config"`
	}

	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, fmt.Sprintf("Invalid request: %v", err), http.StatusBadRequest)
		return
	}

	if request.Name == "" {
		http.Error(w, "Preset name is required", http.StatusBadRequest)
		return
	}

	presetsDir := s.getHarvestersPresetsDir()

	// Ensure directory exists
	if err := os.MkdirAll(presetsDir, 0755); err != nil {
		http.Error(w, fmt.Sprintf("Failed to create presets directory: %v", err), http.StatusInternalServerError)
		return
	}

	// Sanitize filename
	filename := sanitizeFilename(request.Name) + ".yml"
	presetPath := filepath.Join(presetsDir, filename)

	if err := credentials.SaveHarvestersConfig(presetPath, &request.Config); err != nil {
		http.Error(w, fmt.Sprintf("Failed to save preset: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"success": true,
		"message": fmt.Sprintf("Preset '%s' saved successfully", request.Name),
	})
}

// handleLoadHarvesterPreset loads a harvester configuration preset
func (s *Server) handleLoadHarvesterPreset(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var request struct {
		Name string `json:"name"`
	}

	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, fmt.Sprintf("Invalid request: %v", err), http.StatusBadRequest)
		return
	}

	if request.Name == "" {
		http.Error(w, "Preset name is required", http.StatusBadRequest)
		return
	}

	presetsDir := s.getHarvestersPresetsDir()
	filename := sanitizeFilename(request.Name) + ".yml"
	presetPath := filepath.Join(presetsDir, filename)

	// Load the preset
	config, err := credentials.LoadHarvestersConfig(presetPath)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to load preset: %v", err), http.StatusNotFound)
		return
	}

	// Save as active configuration
	configPath := s.getHarvestersConfigPath()
	if err := credentials.SaveHarvestersConfig(configPath, config); err != nil {
		http.Error(w, fmt.Sprintf("Failed to apply preset: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"success": true,
		"message": fmt.Sprintf("Preset '%s' loaded successfully. Restart capture to apply changes.", request.Name),
		"config":  config,
	})
}

// handleDeleteHarvesterPreset deletes a harvester configuration preset
func (s *Server) handleDeleteHarvesterPreset(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var request struct {
		Name string `json:"name"`
	}

	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, fmt.Sprintf("Invalid request: %v", err), http.StatusBadRequest)
		return
	}

	if request.Name == "" {
		http.Error(w, "Preset name is required", http.StatusBadRequest)
		return
	}

	presetsDir := s.getHarvestersPresetsDir()
	filename := sanitizeFilename(request.Name) + ".yml"
	presetPath := filepath.Join(presetsDir, filename)

	if err := os.Remove(presetPath); err != nil {
		http.Error(w, fmt.Sprintf("Failed to delete preset: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"success": true,
		"message": fmt.Sprintf("Preset '%s' deleted successfully", request.Name),
	})
}

// handleUploadHarvesterPreset handles uploading a harvester configuration preset file
func (s *Server) handleUploadHarvesterPreset(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse multipart form (limit to 10MB)
	if err := r.ParseMultipartForm(10 << 20); err != nil {
		http.Error(w, fmt.Sprintf("Failed to parse form: %v", err), http.StatusBadRequest)
		return
	}

	// Get the uploaded file
	file, header, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "No file provided", http.StatusBadRequest)
		return
	}
	defer file.Close()

	// Validate file extension
	if !strings.HasSuffix(header.Filename, ".yml") && !strings.HasSuffix(header.Filename, ".yaml") {
		http.Error(w, "Invalid file type. Only .yml and .yaml files are allowed", http.StatusBadRequest)
		return
	}

	// Read and validate the configuration
	data, err := io.ReadAll(file)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to read file: %v", err), http.StatusBadRequest)
		return
	}

	// Validate YAML by attempting to load it
	tmpFile := filepath.Join(os.TempDir(), "harvester-upload-temp.yml")
	if err := os.WriteFile(tmpFile, data, 0644); err != nil {
		http.Error(w, fmt.Sprintf("Failed to write temp file: %v", err), http.StatusInternalServerError)
		return
	}
	defer os.Remove(tmpFile)

	config, err := credentials.LoadHarvestersConfig(tmpFile)
	if err != nil {
		http.Error(w, fmt.Sprintf("Invalid configuration file: %v", err), http.StatusBadRequest)
		return
	}

	// Get configuration name from form or use filename
	configName := r.FormValue("name")
	if configName == "" {
		configName = strings.TrimSuffix(header.Filename, filepath.Ext(header.Filename))
	}

	// Sanitize the name
	configName = sanitizeFilename(configName)

	presetsDir := s.getHarvestersPresetsDir()

	// Ensure directory exists
	if err := os.MkdirAll(presetsDir, 0755); err != nil {
		http.Error(w, fmt.Sprintf("Failed to create presets directory: %v", err), http.StatusInternalServerError)
		return
	}

	// Save the preset
	presetPath := filepath.Join(presetsDir, configName+".yml")
	if err := credentials.SaveHarvestersConfig(presetPath, config); err != nil {
		http.Error(w, fmt.Sprintf("Failed to save preset: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"success": true,
		"message": fmt.Sprintf("Preset '%s' uploaded successfully", configName),
		"name":    configName,
	})
}

// handleDownloadHarvesterPreset downloads a harvester configuration preset file
func (s *Server) handleDownloadHarvesterPreset(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Get preset name from query parameter
	presetName := r.URL.Query().Get("name")
	if presetName == "" {
		http.Error(w, "Preset name is required", http.StatusBadRequest)
		return
	}

	presetsDir := s.getHarvestersPresetsDir()
	filename := sanitizeFilename(presetName) + ".yml"
	presetPath := filepath.Join(presetsDir, filename)

	// Check if file exists
	if _, err := os.Stat(presetPath); os.IsNotExist(err) {
		http.Error(w, "Preset not found", http.StatusNotFound)
		return
	}

	// Read the file
	data, err := os.ReadFile(presetPath)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to read preset: %v", err), http.StatusInternalServerError)
		return
	}

	// Set headers for download
	w.Header().Set("Content-Type", "application/x-yaml")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s", filename))
	w.Write(data)
}

// getHarvestersConfigPath returns the path to the active harvester configuration file
func (s *Server) getHarvestersConfigPath() string {
	configRoot := getConfigRootPath()
	return filepath.Join(configRoot, "harvesters-config.yml")
}

// getHarvestersPresetsDir returns the directory for harvester configuration presets
func (s *Server) getHarvestersPresetsDir() string {
	configRoot := getConfigRootPath()
	return filepath.Join(configRoot, "harvester-configs")
}
