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
func CreateEnvironment(record types.AuditRecord) map[string]interface{} {
	env := make(map[string]interface{})

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
	if v.Kind() == reflect.Ptr {
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
func convertFieldValue(v reflect.Value) interface{} {
	// Handle nil pointers
	if !v.IsValid() {
		return nil
	}

	// Dereference pointers
	if v.Kind() == reflect.Ptr {
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
		result := make([]interface{}, length)
		for i := 0; i < length; i++ {
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
func structToMap(v reflect.Value) map[string]interface{} {
	if v.Kind() == reflect.Ptr {
		if v.IsNil() {
			return nil
		}
		v = v.Elem()
	}

	if v.Kind() != reflect.Struct {
		return nil
	}

	result := make(map[string]interface{})
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
