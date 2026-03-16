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
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"

	"github.com/dreadl0ck/netcap/decoder/packet"
	"github.com/dreadl0ck/netcap/decoder/stream"
	netio "github.com/dreadl0ck/netcap/io"
	"github.com/dreadl0ck/netcap/types"
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
			Name:        stripNCPrefix(name),
			Description: d.GetDescription(),
			Type:        "packet",
			Enabled:     enabledMap[name],
		})
	}

	// Get gopacket decoders
	for _, d := range packet.GetGoPacketDecoders() {
		name := d.GetName()
		response.GoPacket = append(response.GoPacket, DecoderInfo{
			Name:        stripNCPrefix(name),
			Description: d.Description,
			Type:        "gopacket",
			Layer:       d.Layer.String(),
			Enabled:     enabledMap[name],
		})
	}

	// Get stream decoders
	for port, d := range stream.DefaultStreamDecoders {
		name := d.GetName()
		response.Stream = append(response.Stream, DecoderInfo{
			Name:        stripNCPrefix(name),
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
			Name:        stripNCPrefix(name),
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
		json.NewEncoder(w).Encode(map[string]any{
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
		included := strings.SplitSeq(config.IncludeDecoders, ",")
		for name := range included {
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
		excludedList := strings.SplitSeq(config.ExcludeDecoders, ",")
		for name := range excludedList {
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

// stripNCPrefix removes the "NC_" prefix from decoder names for display
func stripNCPrefix(name string) string {
	return strings.TrimPrefix(name, "NC_")
}

// getAllDecoderNames returns a list of all decoder names
func (s *Server) getAllDecoderNames() []string {
	packetDecoders := packet.GetPacketDecoders()
	goPacketDecoders := packet.GetGoPacketDecoders()
	streamDecoders := stream.DefaultStreamDecoders
	abstractDecoders := stream.DefaultAbstractDecoders

	names := make([]string, 0, len(packetDecoders)+len(goPacketDecoders)+len(streamDecoders)+len(abstractDecoders))

	// Packet decoders
	for _, d := range packetDecoders {
		names = append(names, d.GetName())
	}

	// GoPacket decoders
	for _, d := range goPacketDecoders {
		names = append(names, d.GetName())
	}

	// Stream decoders
	for _, d := range streamDecoders {
		names = append(names, d.GetName())
	}

	// Abstract decoders
	for _, d := range abstractDecoders {
		names = append(names, d.GetName())
	}

	return names
}

// FieldInfo represents information about a field in an audit record
type FieldInfo struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

// DecoderFieldsResponse represents the response with field information for a decoder
type DecoderFieldsResponse struct {
	DecoderName string      `json:"decoderName"`
	Fields      []FieldInfo `json:"fields"`
}

// handleAllDecoderFields returns field information for all decoders
// URL: /api/decoders/fields
func (s *Server) handleAllDecoderFields(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Get all decoder names
	allNames := s.getAllDecoderNames()

	// Build response map: decoder name -> field info array
	response := make(map[string][]FieldInfo)

	for _, decoderName := range allNames {
		// Skip NC_Header as it's a file header type, not an audit record type
		if decoderName == "NC_Header" {
			continue
		}

		// Add NC_ prefix if not present (needed for stream and abstract decoders)
		typeName := decoderName
		if !strings.HasPrefix(typeName, "NC_") {
			typeName = "NC_" + decoderName
		}

		// Check if the type value exists in the type map
		typeValue, exists := types.Type_value[typeName]
		if !exists {
			continue
		}

		// Try to get the audit record type for this decoder
		record := netio.InitRecord(types.Type(typeValue))
		if record == nil {
			continue
		}

		// Get field names from CSVHeader if it implements AuditRecord
		if auditRecord, ok := record.(types.AuditRecord); ok {
			headers := auditRecord.CSVHeader()

			// Use reflection to get field types
			recordType := reflect.TypeOf(record).Elem()
			fieldTypes := make(map[string]string)

			for i := 0; i < recordType.NumField(); i++ {
				field := recordType.Field(i)
				fieldTypes[field.Name] = getSimplifiedTypeName(field.Type)
			}

			fields := make([]FieldInfo, 0, len(headers))
			// Create field info for each CSV header
			for _, header := range headers {
				fieldType := "unknown"
				// Match header name to struct field name (they're usually the same)
				for i := 0; i < recordType.NumField(); i++ {
					field := recordType.Field(i)
					if strings.EqualFold(field.Name, header) || field.Name == header {
						fieldType = fieldTypes[field.Name]
						break
					}
				}

				fields = append(fields, FieldInfo{
					Name: header,
					Type: fieldType,
				})
			}

			response[stripNCPrefix(decoderName)] = fields
		}
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		http.Error(w, fmt.Sprintf("Failed to encode response: %v", err), http.StatusInternalServerError)
	}
}

// handleDecoderFields returns field information for a specific decoder
// URL: /api/decoders/{decoderName}/fields
func (s *Server) handleDecoderFields(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Extract decoder name from URL path
	// Path format: /api/decoders/{name}/fields
	encodedPath := strings.TrimPrefix(r.URL.Path, "/api/decoders/")
	pathParts := strings.Split(encodedPath, "/")

	// Debug logging
	fmt.Printf("[WebUI] Decoder fields request: path=%s, parts=%v, len=%d\n", r.URL.Path, pathParts, len(pathParts))

	if len(pathParts) < 2 || pathParts[1] != "fields" {
		http.Error(w, fmt.Sprintf("Invalid path format. Expected: /api/decoders/{name}/fields, got: %s", r.URL.Path), http.StatusBadRequest)
		return
	}

	// URL-decode the decoder name
	decoderName, err := url.PathUnescape(pathParts[0])
	if err != nil {
		http.Error(w, "Invalid decoder name encoding", http.StatusBadRequest)
		return
	}

	if decoderName == "" {
		http.Error(w, "Decoder name is required", http.StatusBadRequest)
		return
	}

	// Add NC_ prefix if not present (needed for stream and abstract decoders)
	typeName := decoderName
	if !strings.HasPrefix(typeName, "NC_") {
		typeName = "NC_" + decoderName
	}

	// Try to get the audit record type for this decoder
	record := netio.InitRecord(types.Type(types.Type_value[typeName]))
	if record == nil {
		http.Error(w, fmt.Sprintf("Unknown decoder: %s", decoderName), http.StatusNotFound)
		return
	}

	// Get field names from CSVHeader if it implements AuditRecord
	if auditRecord, ok := record.(types.AuditRecord); ok {
		headers := auditRecord.CSVHeader()

		// Use reflection to get field types
		recordType := reflect.TypeOf(record).Elem()
		fieldTypes := make(map[string]string)

		for i := 0; i < recordType.NumField(); i++ {
			field := recordType.Field(i)
			fieldTypes[field.Name] = getSimplifiedTypeName(field.Type)
		}

		fields := make([]FieldInfo, 0, len(headers))
		// Create field info for each CSV header
		for _, header := range headers {
			fieldType := "unknown"
			// Match header name to struct field name (they're usually the same)
			for i := 0; i < recordType.NumField(); i++ {
				field := recordType.Field(i)
				if strings.EqualFold(field.Name, header) || field.Name == header {
					fieldType = fieldTypes[field.Name]
					break
				}
			}

			fields = append(fields, FieldInfo{
				Name: header,
				Type: fieldType,
			})
		}

		response := DecoderFieldsResponse{
			DecoderName: stripNCPrefix(decoderName),
			Fields:      fields,
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(response); err != nil {
			http.Error(w, fmt.Sprintf("Failed to encode response: %v", err), http.StatusInternalServerError)
		}
		return
	}

	// Fallback: use reflection to get all exported fields
	recordType := reflect.TypeOf(record).Elem()
	fields := make([]FieldInfo, 0, recordType.NumField())
	for i := 0; i < recordType.NumField(); i++ {
		field := recordType.Field(i)
		if field.IsExported() {
			fields = append(fields, FieldInfo{
				Name: field.Name,
				Type: getSimplifiedTypeName(field.Type),
			})
		}
	}

	response := DecoderFieldsResponse{
		DecoderName: stripNCPrefix(decoderName),
		Fields:      fields,
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		http.Error(w, fmt.Sprintf("Failed to encode response: %v", err), http.StatusInternalServerError)
	}
}

// GetTypeValue checks if a decoder name has a corresponding type value
func GetTypeValue(name string) (int32, bool) {
	// Add NC_ prefix if not present
	typeName := name
	if !strings.HasPrefix(typeName, "NC_") {
		typeName = "NC_" + name
	}
	typeValue, ok := types.Type_value[typeName]
	return typeValue, ok
}

// InitRecordForDecoder initializes an audit record for the given decoder name
func InitRecordForDecoder(decoderName string) any {
	// Add NC_ prefix if not present
	typeName := decoderName
	if !strings.HasPrefix(typeName, "NC_") {
		typeName = "NC_" + decoderName
	}
	return netio.InitRecord(types.Type(types.Type_value[typeName]))
}

// GetRecordFields extracts field information from an audit record
// This includes nested fields using dot notation (e.g., "ReqCookies.Name")
func GetRecordFields(record any) []FieldInfo {
	var fields []FieldInfo

	v := reflect.ValueOf(record)
	if v.Kind() == reflect.Pointer {
		v = v.Elem()
	}

	if v.Kind() != reflect.Struct {
		return fields
	}

	// Extract fields recursively, including nested fields
	extractRecordFieldsRecursive(v, "", &fields, 0, 3) // max depth of 3

	return fields
}

// extractRecordFieldsRecursive recursively extracts fields from a struct, including map keys from actual data
func extractRecordFieldsRecursive(v reflect.Value, prefix string, fields *[]FieldInfo, depth int, maxDepth int) {
	if depth >= maxDepth {
		return
	}

	if v.Kind() == reflect.Pointer {
		if v.IsNil() {
			v = reflect.New(v.Type().Elem()).Elem()
		} else {
			v = v.Elem()
		}
	}

	if v.Kind() != reflect.Struct {
		return
	}

	t := v.Type()
	for i := 0; i < v.NumField(); i++ {
		field := v.Field(i)
		fieldType := t.Field(i)

		// Skip unexported fields
		if !fieldType.IsExported() {
			continue
		}

		fieldName := fieldType.Name
		if prefix != "" {
			fieldName = prefix + "." + fieldName
		}

		shouldRecurse := false
		typeName := ""

		switch field.Kind() {
		case reflect.Map:
			// Handle maps by extracting keys from actual data
			if field.Len() > 0 {
				// Map has data - extract keys
				for _, key := range field.MapKeys() {
					mapKeyName := fieldName + "." + key.String()
					mapValue := field.MapIndex(key)

					// Determine type of map values
					var mapTypeName string
					switch mapValue.Kind() {
					case reflect.String:
						if mapValue.String() != "" {
							mapTypeName = "string"
						}
					case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
						if mapValue.Int() != 0 {
							mapTypeName = "int"
						}
					case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
						if mapValue.Uint() != 0 {
							mapTypeName = "uint"
						}
					case reflect.Float32, reflect.Float64:
						if mapValue.Float() != 0 {
							mapTypeName = "float"
						}
					case reflect.Bool:
						mapTypeName = "bool"
					}

					if mapTypeName != "" {
						*fields = append(*fields, FieldInfo{
							Name: mapKeyName,
							Type: mapTypeName,
						})
					}
				}
				shouldRecurse = true // Skip adding the map itself as a field
			}
		case reflect.Slice:
			elemType := field.Type().Elem()
			if elemType.Kind() == reflect.Struct || (elemType.Kind() == reflect.Pointer && elemType.Elem().Kind() == reflect.Struct) {
				// Slice of structs - recurse into the first element if available
				shouldRecurse = true
				var elemValue reflect.Value
				if field.Len() > 0 {
					elemValue = field.Index(0)
					if elemValue.Kind() == reflect.Pointer {
						if !elemValue.IsNil() {
							elemValue = elemValue.Elem()
						} else {
							// Create zero value for inspection
							elemValue = reflect.New(elemType.Elem()).Elem()
						}
					}
				} else if v.IsZero() {
					// Creating zero value for structure inspection
					if elemType.Kind() == reflect.Pointer {
						elemValue = reflect.New(elemType.Elem()).Elem()
					} else {
						elemValue = reflect.New(elemType).Elem()
					}
				}
				if elemValue.IsValid() {
					extractRecordFieldsRecursive(elemValue, fieldName, fields, depth+1, maxDepth)
				}
			} else {
				// Only include slice if it has data or we're doing structure inspection
				if field.Len() > 0 || v.IsZero() {
					typeName = getSimplifiedTypeName(field.Type())
				}
			}
		case reflect.Struct:
			// Nested struct - recurse into it
			shouldRecurse = true
			extractRecordFieldsRecursive(field, fieldName, fields, depth+1, maxDepth)
		case reflect.Pointer:
			// Pointer to struct - recurse into it
			if field.Type().Elem().Kind() == reflect.Struct {
				shouldRecurse = true
				var elemValue reflect.Value
				if field.IsNil() {
					elemValue = reflect.New(field.Type().Elem()).Elem()
				} else {
					elemValue = field.Elem()
				}
				extractRecordFieldsRecursive(elemValue, fieldName, fields, depth+1, maxDepth)
			} else {
				// Pointer to non-struct type
				typeName = getSimplifiedTypeName(field.Type())
			}
		case reflect.String:
			// Only include strings with data
			if field.String() != "" || v.IsZero() {
				typeName = getSimplifiedTypeName(field.Type())
			}
		case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
			// Only include non-zero integers
			if field.Int() != 0 || v.IsZero() {
				typeName = getSimplifiedTypeName(field.Type())
			}
		case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
			// Only include non-zero unsigned integers
			if field.Uint() != 0 || v.IsZero() {
				typeName = getSimplifiedTypeName(field.Type())
			}
		case reflect.Float32, reflect.Float64:
			// Only include non-zero floats
			if field.Float() != 0 || v.IsZero() {
				typeName = getSimplifiedTypeName(field.Type())
			}
		default:
			// Regular field type
			typeName = getSimplifiedTypeName(field.Type())
		}

		if !shouldRecurse && typeName != "" {
			*fields = append(*fields, FieldInfo{
				Name: fieldName,
				Type: typeName,
			})
		}
	}
}

// getSimplifiedTypeName returns a simplified, human-readable type name
func getSimplifiedTypeName(t reflect.Type) string {
	switch t.Kind() {
	case reflect.Bool:
		return "bool"
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return "int"
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return "uint"
	case reflect.Float32, reflect.Float64:
		return "float"
	case reflect.String:
		return "string"
	case reflect.Slice:
		return "[]" + getSimplifiedTypeName(t.Elem())
	case reflect.Array:
		return fmt.Sprintf("[%d]%s", t.Len(), getSimplifiedTypeName(t.Elem()))
	case reflect.Pointer:
		return "*" + getSimplifiedTypeName(t.Elem())
	case reflect.Struct:
		// For structs, return the type name without package
		name := t.Name()
		if name == "" {
			return "struct"
		}
		return name
	default:
		return t.String()
	}
}

// DecoderConfigFile represents metadata about a saved decoder configuration file
type DecoderConfigFile struct {
	Name         string `json:"name"`
	Path         string `json:"path"`
	ModifiedTime int64  `json:"modifiedTime"`
	Size         int64  `json:"size"`
}

// handleListDecoderConfigs returns a list of saved decoder configuration files
func (s *Server) handleListDecoderConfigs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	configRoot := getConfigRootPath()
	configDir := filepath.Join(configRoot, "decoder-configs")

	// Ensure directory exists
	if err := os.MkdirAll(configDir, 0755); err != nil {
		http.Error(w, fmt.Sprintf("Failed to access config directory: %v", err), http.StatusInternalServerError)
		return
	}

	// Read directory
	files, err := os.ReadDir(configDir)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to read config directory: %v", err), http.StatusInternalServerError)
		return
	}

	configFiles := make([]DecoderConfigFile, 0)
	for _, file := range files {
		// Only include .json files
		if file.IsDir() || !strings.HasSuffix(file.Name(), ".json") {
			continue
		}

		info, err := file.Info()
		if err != nil {
			continue
		}

		configFiles = append(configFiles, DecoderConfigFile{
			Name:         strings.TrimSuffix(file.Name(), ".json"),
			Path:         filepath.Join(configDir, file.Name()),
			ModifiedTime: info.ModTime().Unix(),
			Size:         info.Size(),
		})
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(configFiles); err != nil {
		http.Error(w, fmt.Sprintf("Failed to encode response: %v", err), http.StatusInternalServerError)
	}
}

// handleLoadDecoderConfig loads a decoder configuration from a file and applies it
func (s *Server) handleLoadDecoderConfig(w http.ResponseWriter, r *http.Request) {
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
		http.Error(w, "Configuration name is required", http.StatusBadRequest)
		return
	}

	configRoot := getConfigRootPath()
	configDir := filepath.Join(configRoot, "decoder-configs")
	configPath := filepath.Join(configDir, sanitizeFilename(request.Name)+".json")

	// Read the configuration file
	data, err := os.ReadFile(configPath)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to read configuration file: %v", err), http.StatusNotFound)
		return
	}

	var config DecoderConfig
	if err := json.Unmarshal(data, &config); err != nil {
		http.Error(w, fmt.Sprintf("Failed to parse configuration file: %v", err), http.StatusBadRequest)
		return
	}

	// Apply the configuration by saving it as the active config
	if err := s.saveDecoderConfig(config); err != nil {
		http.Error(w, fmt.Sprintf("Failed to apply configuration: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"success": true,
		"message": fmt.Sprintf("Configuration '%s' loaded successfully", request.Name),
		"config":  config,
	})
}

// handleUploadDecoderConfig handles uploading a decoder configuration file
func (s *Server) handleUploadDecoderConfig(w http.ResponseWriter, r *http.Request) {
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
	if !strings.HasSuffix(header.Filename, ".json") {
		http.Error(w, "Invalid file type. Only .json files are allowed", http.StatusBadRequest)
		return
	}

	// Read and validate the configuration
	var config DecoderConfig
	if err := json.NewDecoder(file).Decode(&config); err != nil {
		http.Error(w, fmt.Sprintf("Invalid configuration file: %v", err), http.StatusBadRequest)
		return
	}

	// Get configuration name from form or use filename
	configName := r.FormValue("name")
	if configName == "" {
		configName = strings.TrimSuffix(header.Filename, ".json")
	}

	// Sanitize the name to ensure it's safe for use as a filename
	configName = sanitizeFilename(configName)

	configRoot := getConfigRootPath()
	configDir := filepath.Join(configRoot, "decoder-configs")

	// Ensure directory exists
	if err := os.MkdirAll(configDir, 0755); err != nil {
		http.Error(w, fmt.Sprintf("Failed to create config directory: %v", err), http.StatusInternalServerError)
		return
	}

	// Save the configuration
	configPath := filepath.Join(configDir, configName+".json")
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to marshal config: %v", err), http.StatusInternalServerError)
		return
	}

	if err := os.WriteFile(configPath, data, 0644); err != nil {
		http.Error(w, fmt.Sprintf("Failed to write config file: %v", err), http.StatusInternalServerError)
		return
	}

	// Check if user wants to apply this configuration immediately
	applyNow := r.FormValue("apply") == "true"
	if applyNow {
		if err := s.saveDecoderConfig(config); err != nil {
			http.Error(w, fmt.Sprintf("Configuration saved but failed to apply: %v", err), http.StatusInternalServerError)
			return
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"success": true,
		"message": fmt.Sprintf("Configuration '%s' uploaded successfully", configName),
		"name":    configName,
		"applied": applyNow,
	})
}

// handleDeleteDecoderConfig deletes a saved decoder configuration file
func (s *Server) handleDeleteDecoderConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete && r.Method != http.MethodPost {
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
		http.Error(w, "Configuration name is required", http.StatusBadRequest)
		return
	}

	configRoot := getConfigRootPath()
	configDir := filepath.Join(configRoot, "decoder-configs")
	configPath := filepath.Join(configDir, sanitizeFilename(request.Name)+".json")

	// Delete the file
	if err := os.Remove(configPath); err != nil {
		if os.IsNotExist(err) {
			http.Error(w, "Configuration not found", http.StatusNotFound)
		} else {
			http.Error(w, fmt.Sprintf("Failed to delete configuration: %v", err), http.StatusInternalServerError)
		}
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"success": true,
		"message": fmt.Sprintf("Configuration '%s' deleted successfully", request.Name),
	})
}

// handleSaveDecoderConfigAs saves the current decoder configuration with a specific name
func (s *Server) handleSaveDecoderConfigAs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var request struct {
		Name   string        `json:"name"`
		Config DecoderConfig `json:"config"`
	}

	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, fmt.Sprintf("Invalid request: %v", err), http.StatusBadRequest)
		return
	}

	if request.Name == "" {
		http.Error(w, "Configuration name is required", http.StatusBadRequest)
		return
	}

	// Sanitize the name to ensure it's safe for use as a filename
	configName := sanitizeFilename(request.Name)

	configRoot := getConfigRootPath()
	configDir := filepath.Join(configRoot, "decoder-configs")

	// Ensure directory exists
	if err := os.MkdirAll(configDir, 0755); err != nil {
		http.Error(w, fmt.Sprintf("Failed to create config directory: %v", err), http.StatusInternalServerError)
		return
	}

	// Save the configuration
	configPath := filepath.Join(configDir, configName+".json")
	data, err := json.MarshalIndent(request.Config, "", "  ")
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to marshal config: %v", err), http.StatusInternalServerError)
		return
	}

	if err := os.WriteFile(configPath, data, 0644); err != nil {
		http.Error(w, fmt.Sprintf("Failed to write config file: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"success": true,
		"message": fmt.Sprintf("Configuration saved as '%s'", configName),
		"name":    configName,
	})
}
