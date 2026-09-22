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

package protobuf

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"go.uber.org/zap"

	"github.com/bufbuild/protocompile"
	"github.com/bufbuild/protocompile/reporter"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// schemaRegistry is the global registry for loaded .proto schemas.
// Initialized once during PostInit if proto search paths are configured.
// Protected by schemaRegistryMu for safe concurrent access.
var (
	schemaRegistry   *SchemaRegistry
	schemaRegistryMu sync.RWMutex
)

// portMessageTypes maps port numbers to fully qualified message type names.
// Populated from --proto-message-types flag (format: "port:package.MessageType").
var portMessageTypes = make(map[int32]string)

// portMessageTypesMu protects portMessageTypes.
var portMessageTypesMu sync.RWMutex

// SchemaRegistry holds compiled .proto file descriptors and provides
// message/field lookup by fully qualified name.
type SchemaRegistry struct {
	mu       sync.RWMutex
	messages map[string]protoreflect.MessageDescriptor // full name -> descriptor
	files    int                                       // number of loaded files
}

// NewSchemaRegistry creates a schema registry by compiling all .proto files
// found in the given search paths. Import resolution follows the same semantics
// as protoc: each search path is a root for import resolution.
func NewSchemaRegistry(searchPaths []string) (*SchemaRegistry, error) {
	var protoFiles []string

	for _, sp := range searchPaths {
		info, err := os.Stat(sp)
		if err != nil {
			return nil, fmt.Errorf("proto search path %q: %w", sp, err)
		}

		if !info.IsDir() {
			// Single .proto file
			if strings.HasSuffix(sp, ".proto") {
				protoFiles = append(protoFiles, sp)
			}
			continue
		}

		// Walk directory for .proto files
		err = filepath.Walk(sp, func(path string, fi os.FileInfo, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if !fi.IsDir() && strings.HasSuffix(fi.Name(), ".proto") {
				// Store relative to search path for import resolution
				rel, relErr := filepath.Rel(sp, path)
				if relErr != nil {
					return relErr
				}
				protoFiles = append(protoFiles, rel)
			}
			return nil
		})
		if err != nil {
			return nil, fmt.Errorf("walking proto search path %q: %w", sp, err)
		}
	}

	if len(protoFiles) == 0 {
		return nil, fmt.Errorf("no .proto files found in search paths: %v", searchPaths)
	}

	// Compile all discovered .proto files
	compiler := protocompile.Compiler{
		Resolver: protocompile.WithStandardImports(
			&protocompile.SourceResolver{
				ImportPaths: searchPaths,
			},
		),
		Reporter: reporter.NewReporter(nil, nil), // suppress warnings
	}

	compiled, err := compiler.Compile(context.Background(), protoFiles...)
	if err != nil {
		return nil, fmt.Errorf("compiling proto files: %w", err)
	}

	reg := &SchemaRegistry{
		messages: make(map[string]protoreflect.MessageDescriptor),
		files:    len(compiled),
	}

	// Index all message types from compiled files
	for _, f := range compiled {
		reg.indexMessages(f.Messages())
	}

	return reg, nil
}

// indexMessages recursively indexes all messages (including nested) from a file.
func (r *SchemaRegistry) indexMessages(msgs protoreflect.MessageDescriptors) {
	for i := range msgs.Len() {
		msg := msgs.Get(i)
		r.messages[string(msg.FullName())] = msg
		// Index nested messages
		r.indexMessages(msg.Messages())
	}
}

// LookupMessage returns the message descriptor for a fully qualified name.
func (r *SchemaRegistry) LookupMessage(fullName string) (protoreflect.MessageDescriptor, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	md, ok := r.messages[fullName]
	return md, ok
}

// FileCount returns the number of compiled .proto files.
func (r *SchemaRegistry) FileCount() int {
	return r.files
}

// MessageCount returns the number of indexed message types.
func (r *SchemaRegistry) MessageCount() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.messages)
}

// MessageInfo describes a protobuf message type for API responses.
type MessageInfo struct {
	FullName  string      `json:"fullName"`
	Package   string      `json:"package"`
	Name      string      `json:"name"`
	ProtoFile string      `json:"protoFile"`
	Fields    []FieldInfo `json:"fields"`
}

// FieldInfo describes a single field within a message.
type FieldInfo struct {
	Name       string          `json:"name"`
	Number     int             `json:"number"`
	Type       string          `json:"type"`
	Label      string          `json:"label"`
	TypeName   string          `json:"typeName,omitempty"`
	EnumValues []EnumValueInfo `json:"enumValues,omitempty"`
}

// EnumValueInfo describes a single enum value.
type EnumValueInfo struct {
	Name   string `json:"name"`
	Number int    `json:"number"`
}

// ListMessages returns information about all indexed message types.
func (r *SchemaRegistry) ListMessages() []MessageInfo {
	r.mu.RLock()
	defer r.mu.RUnlock()

	result := make([]MessageInfo, 0, len(r.messages))
	for _, md := range r.messages {
		info := MessageInfo{
			FullName:  string(md.FullName()),
			Package:   string(md.ParentFile().Package()),
			Name:      string(md.Name()),
			ProtoFile: string(md.ParentFile().Path()),
		}

		fields := md.Fields()
		info.Fields = make([]FieldInfo, fields.Len())
		for i := range fields.Len() {
			fd := fields.Get(i)
			fi := FieldInfo{
				Name:   string(fd.Name()),
				Number: int(fd.Number()),
				Type:   fd.Kind().String(),
				Label:  labelString(fd),
			}

			if fd.Kind() == protoreflect.MessageKind || fd.Kind() == protoreflect.GroupKind {
				fi.TypeName = string(fd.Message().FullName())
			}

			if fd.Kind() == protoreflect.EnumKind {
				fi.TypeName = string(fd.Enum().FullName())
				evs := fd.Enum().Values()
				fi.EnumValues = make([]EnumValueInfo, evs.Len())
				for j := range evs.Len() {
					ev := evs.Get(j)
					fi.EnumValues[j] = EnumValueInfo{
						Name:   string(ev.Name()),
						Number: int(ev.Number()),
					}
				}
			}

			info.Fields[i] = fi
		}

		result = append(result, info)
	}

	return result
}

// MessageNames returns all fully qualified message names.
func (r *SchemaRegistry) MessageNames() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	names := make([]string, 0, len(r.messages))
	for name := range r.messages {
		names = append(names, name)
	}
	return names
}

func labelString(fd protoreflect.FieldDescriptor) string {
	if fd.IsList() {
		return "repeated"
	}
	if fd.HasOptionalKeyword() {
		return "optional"
	}
	if fd.Cardinality() == protoreflect.Required {
		return "required"
	}
	return ""
}

// ResolveFields takes raw wire-format fields and a message descriptor,
// and returns a map of named fields with their values.
// Unknown field numbers (not in schema) are kept with their wire-format keys.
func ResolveFields(fields []Field, md protoreflect.MessageDescriptor) map[string]string {
	named := make(map[string]string, len(fields))
	fieldDescs := md.Fields()

	for _, f := range fields {
		fd := fieldDescs.ByNumber(protoreflect.FieldNumber(f.Number))
		if fd == nil {
			// Unknown field — keep wire-format key
			key := fmt.Sprintf("%s_%d", f.Type, f.Number)
			named[key] = f.Value
			continue
		}

		name := string(fd.Name())
		value := f.Value

		// Resolve enum labels
		if fd.Kind() == protoreflect.EnumKind && f.Type == "varint" {
			if v, err := strconv.ParseInt(f.Value, 10, 32); err == nil {
				enumDesc := fd.Enum()
				if ev := enumDesc.Values().ByNumber(protoreflect.EnumNumber(v)); ev != nil {
					value = string(ev.Name())
				}
			}
		}

		named[name] = value
	}

	return named
}

// GetSchemaRegistry returns the global schema registry in a thread-safe manner.
func GetSchemaRegistry() *SchemaRegistry {
	schemaRegistryMu.RLock()
	defer schemaRegistryMu.RUnlock()
	return schemaRegistry
}

// SetSchemaRegistry sets the global schema registry in a thread-safe manner.
func SetSchemaRegistry(r *SchemaRegistry) {
	schemaRegistryMu.Lock()
	defer schemaRegistryMu.Unlock()
	schemaRegistry = r
}

// ParseMessageTypeMappings parses "port:MessageType" strings into portMessageTypes.
func ParseMessageTypeMappings(mappings []string) {
	portMessageTypesMu.Lock()
	defer portMessageTypesMu.Unlock()

	for _, m := range mappings {
		parts := strings.SplitN(m, ":", 2)
		if len(parts) != 2 {
			pbLog.Warn("invalid proto-message-type mapping, expected port:MessageType", zap.String("value", m))
			continue
		}
		port, err := strconv.ParseInt(parts[0], 10, 32)
		if err != nil {
			pbLog.Warn("invalid port in proto-message-type mapping", zap.String("value", m), zap.Error(err))
			continue
		}
		portMessageTypes[int32(port)] = parts[1]
	}
}

// lookupMessageTypeByPort returns the message type name for a port, if configured.
func lookupMessageTypeByPort(port int32) (string, bool) {
	portMessageTypesMu.RLock()
	defer portMessageTypesMu.RUnlock()
	mt, ok := portMessageTypes[port]
	return mt, ok
}
