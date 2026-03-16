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

package filter

import (
	"fmt"
	"reflect"

	"github.com/expr-lang/expr"
	"github.com/expr-lang/expr/vm"
	"github.com/gogo/protobuf/proto"

	netio "github.com/dreadl0ck/netcap/io"
	"github.com/dreadl0ck/netcap/types"
)

// CompiledFilter wraps a compiled expression program with its record type.
type CompiledFilter struct {
	Program    *vm.Program
	RecordType types.Type
	Expression string
}

// CompileExpression compiles an expr-lang expression for a specific audit record type.
// The expression has access to all fields of the audit record and helper functions.
func CompileExpression(expression string, recordType types.Type) (*vm.Program, error) {
	if expression == "" {
		return nil, fmt.Errorf("empty expression")
	}

	// Create a sample record to extract the type structure
	record := netio.InitRecord(recordType)
	if record == nil {
		return nil, fmt.Errorf("unsupported record type: %s", recordType.String())
	}

	// Create the environment with the record fields and helper functions
	env := CreateEnvironment(record.(types.AuditRecord))

	// Compile the expression with the environment and explicit function signatures
	// This ensures proper type inference for array literals and other complex types
	program, err := expr.Compile(expression,
		expr.Env(env),
		expr.AsBool(),
		// Network helper functions with explicit type signatures
		expr.Function("InSubnet",
			func(params ...any) (any, error) {
				return InSubnet(params[0].(string), params[1].(string)), nil
			},
			new(func(string, string) bool),
		),
		expr.Function("IsPrivateIP",
			func(params ...any) (any, error) {
				return IsPrivateIP(params[0].(string)), nil
			},
			new(func(string) bool),
		),
		expr.Function("IsPublicIP",
			func(params ...any) (any, error) {
				return IsPublicIP(params[0].(string)), nil
			},
			new(func(string) bool),
		),
		expr.Function("ParsePort",
			func(params ...any) (any, error) {
				return ParsePort(params[0].(string)), nil
			},
			new(func(string) int),
		),
		expr.Function("PortInRange",
			func(params ...any) (any, error) {
				return PortInRange(params[0].(int), params[1].(int), params[2].(int)), nil
			},
			new(func(int, int, int) bool),
		),
		// Time helper functions with explicit type signatures
		expr.Function("TimeInRange",
			func(params ...any) (any, error) {
				return TimeInRange(params[0].(int64), params[1].(int64), params[2].(int64)), nil
			},
			new(func(int64, int64, int64) bool),
		),
		expr.Function("DurationSince",
			func(params ...any) (any, error) {
				return DurationSince(params[0].(int64)), nil
			},
			new(func(int64) int64),
		),
		expr.Function("FormatTime",
			func(params ...any) (any, error) {
				return FormatTime(params[0].(int64), params[1].(string)), nil
			},
			new(func(int64, string) string),
		),
		// String helper functions with explicit type signatures
		expr.Function("ContainsAny",
			func(params ...any) (any, error) {
				str := params[0].(string)
				// Handle variadic string parameters (array literal in expression)
				substrs := make([]string, len(params)-1)
				for i := 1; i < len(params); i++ {
					substrs[i-1] = params[i].(string)
				}
				return ContainsAny(str, substrs), nil
			},
			new(func(string, ...string) bool),
		),
		expr.Function("MatchesPattern",
			func(params ...any) (any, error) {
				return MatchesPattern(params[0].(string), params[1].(string)), nil
			},
			new(func(string, string) bool),
		),
		expr.Function("Contains",
			func(params ...any) (any, error) {
				return Contains(params[0], params[1]), nil
			},
			new(func(any, any) bool),
		),
		expr.Function("HasKey",
			func(params ...any) (any, error) {
				return HasKey(params[0], params[1].(string)), nil
			},
			new(func(any, string) bool),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to compile expression: %w", err)
	}

	return program, nil
}

// EvaluateExpression evaluates a compiled expression against an audit record.
// Returns true if the record matches the filter, false otherwise.
func EvaluateExpression(program *vm.Program, record types.AuditRecord) (bool, error) {
	if program == nil {
		return true, nil // No filter means all records pass
	}

	env := CreateEnvironment(record)

	// Add helper functions to the evaluation environment
	// These are used at runtime, while type information comes from expr.Function() at compile time
	env["InSubnet"] = InSubnet
	env["IsPrivateIP"] = IsPrivateIP
	env["IsPublicIP"] = IsPublicIP
	env["ParsePort"] = ParsePort
	env["PortInRange"] = PortInRange
	env["TimeInRange"] = TimeInRange
	env["DurationSince"] = DurationSince
	env["FormatTime"] = FormatTime
	env["ContainsAny"] = ContainsAny
	env["MatchesPattern"] = MatchesPattern
	env["Contains"] = Contains
	env["HasKey"] = HasKey

	result, err := expr.Run(program, env)
	if err != nil {
		return false, fmt.Errorf("failed to evaluate expression: %w", err)
	}

	match, ok := result.(bool)
	if !ok {
		return false, fmt.Errorf("expression did not return a boolean value: got %T", result)
	}

	return match, nil
}

// CreateEnvironment creates an expression environment from an audit record.
// This makes all fields of the record accessible in expressions.
// Note: Helper functions are declared via expr.Function() in CompileExpression() with explicit type signatures.
func CreateEnvironment(record types.AuditRecord) map[string]any {
	env := make(map[string]any)

	// Helper functions are now declared in CompileExpression() using expr.Function()
	// with explicit type signatures to ensure proper type inference for array literals.
	// They are NOT added to the environment here to avoid type conflicts.

	// Convert the record to a map for field access
	protoMsg, ok := record.(proto.Message)
	if !ok {
		return env
	}

	// Use reflection to extract all fields from the protobuf message
	v := reflect.ValueOf(protoMsg)
	if v.Kind() == reflect.Pointer {
		v = v.Elem()
	}

	t := v.Type()
	for i := 0; i < v.NumField(); i++ {
		field := t.Field(i)
		fieldValue := v.Field(i)

		// Skip unexported fields
		if !fieldValue.CanInterface() {
			continue
		}

		// Add the field to the environment
		// For nested structs, we need to expose them properly for dot notation
		env[field.Name] = convertFieldValue(fieldValue)
	}

	return env
}

// convertFieldValue converts a reflect.Value to a suitable interface{} for expr-lang.
// This handles nested structs, pointers, and ensures proper field access.
func convertFieldValue(v reflect.Value) any {
	// Handle nil pointers
	if !v.IsValid() {
		return nil
	}

	// Dereference pointers
	if v.Kind() == reflect.Pointer {
		if v.IsNil() {
			return nil
		}
		v = v.Elem()
	}

	// For structs, convert to a map to enable nested field access
	if v.Kind() == reflect.Struct {
		return structToMap(v)
	}

	// For slices of structs, convert each element
	if v.Kind() == reflect.Slice {
		length := v.Len()
		result := make([]any, length)
		for i := range length {
			elem := v.Index(i)
			result[i] = convertFieldValue(elem)
		}
		return result
	}

	// For other types, return the interface directly
	if v.CanInterface() {
		return v.Interface()
	}

	return nil
}

// structToMap converts a struct to a map for nested field access in expressions.
func structToMap(v reflect.Value) map[string]any {
	if v.Kind() == reflect.Pointer {
		if v.IsNil() {
			return nil
		}
		v = v.Elem()
	}

	if v.Kind() != reflect.Struct {
		return nil
	}

	result := make(map[string]any)
	t := v.Type()

	for i := 0; i < v.NumField(); i++ {
		field := t.Field(i)
		fieldValue := v.Field(i)

		// Skip unexported fields
		if !fieldValue.CanInterface() {
			continue
		}

		// Recursively convert nested structures
		result[field.Name] = convertFieldValue(fieldValue)
	}

	return result
}

// MustCompileExpression compiles an expression and panics on error.
// Useful for static expressions that are known to be valid.
func MustCompileExpression(expression string, recordType types.Type) *vm.Program {
	program, err := CompileExpression(expression, recordType)
	if err != nil {
		panic(err)
	}
	return program
}
