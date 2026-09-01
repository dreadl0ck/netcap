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
	"strconv"
	"strings"
	"sync"
	"time"

	decoderconfig "github.com/dreadl0ck/netcap/decoder/config"
	pb "github.com/dreadl0ck/netcap/decoder/stream/protobuf"
)

// protoState tracks the runtime state of protobuf schema configuration.
type protoState struct {
	mu            sync.RWMutex
	searchPaths   []string
	uploadDir     string // directory for uploaded .proto files
	errors        []string
	lastCompiled  time.Time
}

var protoRuntime = &protoState{}

// ProtoStatusResponse is the response for GET /api/proto/status.
type ProtoStatusResponse struct {
	Loaded           bool              `json:"loaded"`
	FileCount        int               `json:"fileCount"`
	MessageCount     int               `json:"messageCount"`
	SearchPaths      []string          `json:"searchPaths"`
	ShowAlternatives bool              `json:"showAlternatives"`
	PortMappings     []PortMapping     `json:"portMappings"`
	Errors           []string          `json:"errors"`
	LastCompiled     string            `json:"lastCompiled"`
}

// PortMapping represents a port-to-message-type mapping.
type PortMapping struct {
	Port        int    `json:"port"`
	MessageType string `json:"messageType"`
}

// ProtoMessagesResponse is the response for GET /api/proto/messages.
type ProtoMessagesResponse struct {
	Messages []pb.MessageInfo `json:"messages"`
}

func (s *Server) getProtoStatus() ProtoStatusResponse {
	protoRuntime.mu.RLock()
	defer protoRuntime.mu.RUnlock()

	resp := ProtoStatusResponse{
		SearchPaths:      protoRuntime.searchPaths,
		ShowAlternatives: decoderconfig.Instance != nil && decoderconfig.Instance.ProtoShowAlternatives,
		Errors:           protoRuntime.errors,
	}

	if len(resp.SearchPaths) == 0 {
		resp.SearchPaths = []string{}
	}
	if len(resp.Errors) == 0 {
		resp.Errors = []string{}
	}

	if !protoRuntime.lastCompiled.IsZero() {
		resp.LastCompiled = protoRuntime.lastCompiled.Format(time.RFC3339)
	}

	reg := pb.GetSchemaRegistry()
	if reg != nil {
		resp.Loaded = true
		resp.FileCount = reg.FileCount()
		resp.MessageCount = reg.MessageCount()
	}

	// Collect port mappings
	resp.PortMappings = getPortMappings()

	return resp
}

func getPortMappings() []PortMapping {
	if decoderconfig.Instance == nil {
		return []PortMapping{}
	}

	var mappings []PortMapping
	for _, m := range decoderconfig.Instance.ProtoMessageTypes {
		parts := strings.SplitN(m, ":", 2)
		if len(parts) != 2 {
			continue
		}
		port, err := strconv.Atoi(parts[0])
		if err != nil {
			continue
		}
		mappings = append(mappings, PortMapping{Port: port, MessageType: parts[1]})
	}
	if mappings == nil {
		mappings = []PortMapping{}
	}
	return mappings
}

// handleProtoStatus handles GET /api/proto/status.
func (s *Server) handleProtoStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(s.getProtoStatus()); err != nil {
		http.Error(w, fmt.Sprintf("Failed to encode response: %v", err), http.StatusInternalServerError)
	}
}

// handleProtoMessages handles GET /api/proto/messages.
func (s *Server) handleProtoMessages(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	reg := pb.GetSchemaRegistry()
	resp := ProtoMessagesResponse{
		Messages: []pb.MessageInfo{},
	}
	if reg != nil {
		resp.Messages = reg.ListMessages()
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		http.Error(w, fmt.Sprintf("Failed to encode response: %v", err), http.StatusInternalServerError)
	}
}

// handleProtoSearchPaths handles POST/DELETE /api/proto/search-paths.
func (s *Server) handleProtoSearchPaths(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Path string `json:"path"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf("Invalid request: %v", err), http.StatusBadRequest)
		return
	}

	if req.Path == "" {
		http.Error(w, "Path is required", http.StatusBadRequest)
		return
	}

	protoRuntime.mu.Lock()

	switch r.Method {
	case http.MethodPost:
		// Validate path exists
		info, err := os.Stat(req.Path)
		if err != nil {
			protoRuntime.mu.Unlock()
			jsonError(w, fmt.Sprintf("Path does not exist: %v", err), http.StatusBadRequest)
			return
		}
		if !info.IsDir() && !strings.HasSuffix(req.Path, ".proto") {
			protoRuntime.mu.Unlock()
			jsonError(w, "Path must be a directory or a .proto file", http.StatusBadRequest)
			return
		}

		// Check for duplicate
		for _, p := range protoRuntime.searchPaths {
			if p == req.Path {
				protoRuntime.mu.Unlock()
				jsonError(w, "Path already added", http.StatusConflict)
				return
			}
		}

		protoRuntime.searchPaths = append(protoRuntime.searchPaths, req.Path)

	case http.MethodDelete:
		newPaths := make([]string, 0, len(protoRuntime.searchPaths))
		for _, p := range protoRuntime.searchPaths {
			if p != req.Path {
				newPaths = append(newPaths, p)
			}
		}
		protoRuntime.searchPaths = newPaths

	default:
		protoRuntime.mu.Unlock()
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	paths := make([]string, len(protoRuntime.searchPaths))
	copy(paths, protoRuntime.searchPaths)
	protoRuntime.mu.Unlock()

	// Recompile schemas with updated paths
	recompileSchemas(paths)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"success": true,
		"message": "Search paths updated",
		"status":  s.getProtoStatus(),
	})
}

// handleProtoUpload handles POST /api/proto/upload (multipart form).
func (s *Server) handleProtoUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse multipart form (max 32MB)
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		jsonError(w, fmt.Sprintf("Failed to parse form: %v", err), http.StatusBadRequest)
		return
	}

	files := r.MultipartForm.File["files"]
	if len(files) == 0 {
		jsonError(w, "No files uploaded", http.StatusBadRequest)
		return
	}

	// Ensure upload directory exists
	protoRuntime.mu.Lock()
	if protoRuntime.uploadDir == "" {
		protoRuntime.uploadDir = filepath.Join(os.TempDir(), "netcap-proto-uploads")
	}
	uploadDir := protoRuntime.uploadDir
	protoRuntime.mu.Unlock()

	if err := os.MkdirAll(uploadDir, 0o755); err != nil {
		jsonError(w, fmt.Sprintf("Failed to create upload directory: %v", err), http.StatusInternalServerError)
		return
	}

	var uploadedFiles []string
	for _, fh := range files {
		if !strings.HasSuffix(fh.Filename, ".proto") {
			continue
		}

		src, err := fh.Open()
		if err != nil {
			log.Printf("[Proto] Failed to open uploaded file %s: %v", fh.Filename, err)
			continue
		}

		dstPath := filepath.Join(uploadDir, fh.Filename)
		dst, err := os.Create(dstPath)
		if err != nil {
			src.Close()
			log.Printf("[Proto] Failed to create file %s: %v", dstPath, err)
			continue
		}

		if _, err = io.Copy(dst, src); err != nil {
			log.Printf("[Proto] Failed to write file %s: %v", dstPath, err)
		}
		dst.Close()
		src.Close()
		uploadedFiles = append(uploadedFiles, fh.Filename)
	}

	if len(uploadedFiles) == 0 {
		jsonError(w, "No valid .proto files uploaded", http.StatusBadRequest)
		return
	}

	// Add upload dir to search paths if not already present
	protoRuntime.mu.Lock()
	hasUploadDir := false
	for _, p := range protoRuntime.searchPaths {
		if p == uploadDir {
			hasUploadDir = true
			break
		}
	}
	if !hasUploadDir {
		protoRuntime.searchPaths = append(protoRuntime.searchPaths, uploadDir)
	}
	paths := make([]string, len(protoRuntime.searchPaths))
	copy(paths, protoRuntime.searchPaths)
	protoRuntime.mu.Unlock()

	// Recompile
	recompileSchemas(paths)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"success":       true,
		"message":       fmt.Sprintf("Uploaded %d file(s)", len(uploadedFiles)),
		"uploadedFiles": uploadedFiles,
		"status":        s.getProtoStatus(),
	})
}

// handleProtoMappings handles GET/POST/DELETE /api/proto/mappings.
func (s *Server) handleProtoMappings(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"mappings": getPortMappings(),
		})

	case http.MethodPost:
		var req struct {
			Port        int    `json:"port"`
			MessageType string `json:"messageType"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			jsonError(w, fmt.Sprintf("Invalid request: %v", err), http.StatusBadRequest)
			return
		}
		if req.Port < 1 || req.Port > 65535 {
			jsonError(w, "Port must be between 1 and 65535", http.StatusBadRequest)
			return
		}
		if req.MessageType == "" {
			jsonError(w, "Message type is required", http.StatusBadRequest)
			return
		}

		mapping := fmt.Sprintf("%d:%s", req.Port, req.MessageType)

		if decoderconfig.Instance != nil {
			decoderconfig.LockInstance()
			// Remove existing mapping for this port
			newMappings := make([]string, 0, len(decoderconfig.Instance.ProtoMessageTypes)+1)
			prefix := fmt.Sprintf("%d:", req.Port)
			for _, m := range decoderconfig.Instance.ProtoMessageTypes {
				if !strings.HasPrefix(m, prefix) {
					newMappings = append(newMappings, m)
				}
			}
			newMappings = append(newMappings, mapping)
			decoderconfig.Instance.ProtoMessageTypes = newMappings
			decoderconfig.UnlockInstance()

			// Re-parse mappings in the protobuf decoder
			pb.ParseMessageTypeMappings(decoderconfig.Instance.ProtoMessageTypes)
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"success": true,
			"message": fmt.Sprintf("Mapping added: port %d -> %s", req.Port, req.MessageType),
		})

	case http.MethodDelete:
		var req struct {
			Port int `json:"port"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			jsonError(w, fmt.Sprintf("Invalid request: %v", err), http.StatusBadRequest)
			return
		}

		if decoderconfig.Instance != nil {
			decoderconfig.LockInstance()
			prefix := fmt.Sprintf("%d:", req.Port)
			newMappings := make([]string, 0, len(decoderconfig.Instance.ProtoMessageTypes))
			for _, m := range decoderconfig.Instance.ProtoMessageTypes {
				if !strings.HasPrefix(m, prefix) {
					newMappings = append(newMappings, m)
				}
			}
			decoderconfig.Instance.ProtoMessageTypes = newMappings
			decoderconfig.UnlockInstance()

			pb.ParseMessageTypeMappings(decoderconfig.Instance.ProtoMessageTypes)
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"success": true,
			"message": fmt.Sprintf("Mapping removed for port %d", req.Port),
		})

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleProtoPreferences handles POST /api/proto/preferences.
func (s *Server) handleProtoPreferences(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		ShowAlternatives bool `json:"showAlternatives"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, fmt.Sprintf("Invalid request: %v", err), http.StatusBadRequest)
		return
	}

	pb.SetShowAlternatives(req.ShowAlternatives)
	if decoderconfig.Instance != nil {
		decoderconfig.LockInstance()
		decoderconfig.Instance.ProtoShowAlternatives = req.ShowAlternatives
		decoderconfig.UnlockInstance()
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"success": true,
		"message": fmt.Sprintf("Show alternatives: %v", req.ShowAlternatives),
	})
}

// handleProtoRecompile handles POST /api/proto/recompile.
func (s *Server) handleProtoRecompile(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	protoRuntime.mu.RLock()
	paths := make([]string, len(protoRuntime.searchPaths))
	copy(paths, protoRuntime.searchPaths)
	protoRuntime.mu.RUnlock()

	if len(paths) == 0 {
		jsonError(w, "No search paths configured", http.StatusBadRequest)
		return
	}

	recompileSchemas(paths)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"success": true,
		"message": "Recompilation complete",
		"status":  s.getProtoStatus(),
	})
}

// recompileSchemas compiles all .proto files from the given search paths
// and updates the global schema registry.
func recompileSchemas(paths []string) {
	protoRuntime.mu.Lock()
	defer protoRuntime.mu.Unlock()

	if len(paths) == 0 {
		protoRuntime.errors = []string{}
		pb.SetSchemaRegistry(nil)
		return
	}

	registry, err := pb.NewSchemaRegistry(paths)
	if err != nil {
		protoRuntime.errors = []string{err.Error()}
		protoRuntime.lastCompiled = time.Now()
		log.Printf("[Proto] Schema compilation failed: %v", err)
		return
	}

	pb.SetSchemaRegistry(registry)
	protoRuntime.errors = []string{}
	protoRuntime.lastCompiled = time.Now()

	// Update decoder config search paths
	if decoderconfig.Instance != nil {
		decoderconfig.LockInstance()
		decoderconfig.Instance.ProtoSearchPaths = paths
		decoderconfig.UnlockInstance()
	}

	log.Printf("[Proto] Schema registry updated: %d files, %d messages", registry.FileCount(), registry.MessageCount())
}

// jsonError sends a JSON error response.
func jsonError(w http.ResponseWriter, message string, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]any{
		"success": false,
		"error":   message,
	})
}
