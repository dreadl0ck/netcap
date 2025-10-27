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
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/dreadl0ck/netcap/decoder/packet"
	"github.com/dreadl0ck/netcap/decoder/stream"
)

// DecoderInfo represents information about a decoder
type DecoderInfo struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Type        string `json:"type"`
	Layer       string `json:"layer,omitempty"`
	Port        int32  `json:"port,omitempty"`
	Enabled     bool   `json:"enabled"`
}

// DecodersResponse represents the response with all decoder information
type DecodersResponse struct {
	Packet   []DecoderInfo `json:"packet"`
	GoPacket []DecoderInfo `json:"gopacket"`
	Stream   []DecoderInfo `json:"stream"`
	Abstract []DecoderInfo `json:"abstract"`
}

// DecoderConfig represents the decoder configuration that can be saved
type DecoderConfig struct {
	IncludeDecoders string   `json:"includeDecoders"`
	ExcludeDecoders string   `json:"excludeDecoders"`
	EnabledDecoders []string `json:"enabledDecoders"`
}

// handleDecoders returns information about all available decoders
func (s *Server) handleDecoders(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Load current configuration
	config := s.loadDecoderConfig()
	enabledMap := s.getEnabledDecodersMap(config)

	response := DecodersResponse{
		Packet:   make([]DecoderInfo, 0),
		GoPacket: make([]DecoderInfo, 0),
		Stream:   make([]DecoderInfo, 0),
		Abstract: make([]DecoderInfo, 0),
	}

	// Get packet decoders
	for _, d := range packet.GetPacketDecoders() {
		name := d.GetName()
		response.Packet = append(response.Packet, DecoderInfo{
			Name:        name,
			Description: d.GetDescription(),
			Type:        "packet",
			Enabled:     enabledMap[name],
		})
	}

	// Get gopacket decoders
	for _, d := range packet.GetGoPacketDecoders() {
		name := d.Layer.String()
		response.GoPacket = append(response.GoPacket, DecoderInfo{
			Name:        name,
			Description: d.Description,
			Type:        "gopacket",
			Layer:       name,
			Enabled:     enabledMap[name],
		})
	}

	// Get stream decoders
	for port, d := range stream.DefaultStreamDecoders {
		name := d.GetName()
		response.Stream = append(response.Stream, DecoderInfo{
			Name:        name,
			Description: d.GetDescription(),
			Type:        "stream",
			Port:        port,
			Enabled:     enabledMap[name],
		})
	}

	// Get abstract decoders
	for _, d := range stream.DefaultAbstractDecoders {
		name := d.GetName()
		response.Abstract = append(response.Abstract, DecoderInfo{
			Name:        name,
			Description: d.GetDescription(),
			Type:        "abstract",
			Enabled:     enabledMap[name],
		})
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		http.Error(w, fmt.Sprintf("Failed to encode response: %v", err), http.StatusInternalServerError)
	}
}

// handleDecoderConfig handles GET and POST requests for decoder configuration
func (s *Server) handleDecoderConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		config := s.loadDecoderConfig()
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(config); err != nil {
			http.Error(w, fmt.Sprintf("Failed to encode response: %v", err), http.StatusInternalServerError)
		}
	case http.MethodPost:
		var config DecoderConfig
		if err := json.NewDecoder(r.Body).Decode(&config); err != nil {
			http.Error(w, fmt.Sprintf("Invalid request: %v", err), http.StatusBadRequest)
			return
		}

		if err := s.saveDecoderConfig(config); err != nil {
			http.Error(w, fmt.Sprintf("Failed to save configuration: %v", err), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"message": "Decoder configuration saved successfully",
		})
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// loadDecoderConfig loads the decoder configuration from file
func (s *Server) loadDecoderConfig() DecoderConfig {
	configPath := s.getDecoderConfigPath()

	data, err := os.ReadFile(configPath)
	if err != nil {
		// Return default config if file doesn't exist
		return DecoderConfig{
			IncludeDecoders: "",
			ExcludeDecoders: "",
			EnabledDecoders: []string{},
		}
	}

	var config DecoderConfig
	if err := json.Unmarshal(data, &config); err != nil {
		// Return default config if file is corrupted
		return DecoderConfig{
			IncludeDecoders: "",
			ExcludeDecoders: "",
			EnabledDecoders: []string{},
		}
	}

	return config
}

// saveDecoderConfig saves the decoder configuration to file
func (s *Server) saveDecoderConfig(config DecoderConfig) error {
	configPath := s.getDecoderConfigPath()

	// Ensure directory exists
	if err := os.MkdirAll(filepath.Dir(configPath), 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	if err := os.WriteFile(configPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}

// getDecoderConfigPath returns the path to the decoder configuration file
func (s *Server) getDecoderConfigPath() string {
	configRoot := getConfigRootPath()
	return filepath.Join(configRoot, "decoder-config.json")
}

// getEnabledDecodersMap returns a map of decoder names to their enabled status
func (s *Server) getEnabledDecodersMap(config DecoderConfig) map[string]bool {
	enabledMap := make(map[string]bool)

	// If there's an include list, only those decoders are enabled
	if config.IncludeDecoders != "" {
		included := strings.Split(config.IncludeDecoders, ",")
		for _, name := range included {
			name = strings.TrimSpace(name)
			if name != "" {
				enabledMap[name] = true
			}
		}
		return enabledMap
	}

	// If there's an exclude list, all decoders except excluded ones are enabled
	excluded := make(map[string]bool)
	if config.ExcludeDecoders != "" {
		excludedList := strings.Split(config.ExcludeDecoders, ",")
		for _, name := range excludedList {
			name = strings.TrimSpace(name)
			if name != "" {
				excluded[name] = true
			}
		}
	}

	// By default, all decoders are enabled unless excluded
	// Get all decoder names
	allNames := s.getAllDecoderNames()
	for _, name := range allNames {
		enabledMap[name] = !excluded[name]
	}

	return enabledMap
}

// getAllDecoderNames returns a list of all decoder names
func (s *Server) getAllDecoderNames() []string {
	names := make([]string, 0)

	// Packet decoders
	for _, d := range packet.GetPacketDecoders() {
		names = append(names, d.GetName())
	}

	// GoPacket decoders
	for _, d := range packet.GetGoPacketDecoders() {
		names = append(names, d.Layer.String())
	}

	// Stream decoders
	for _, d := range stream.DefaultStreamDecoders {
		names = append(names, d.GetName())
	}

	// Abstract decoders
	for _, d := range stream.DefaultAbstractDecoders {
		names = append(names, d.GetName())
	}

	return names
}
