// Package apipolicy implements positive API validation from pinned local artifacts.
// It neither selects an upstream nor authenticates a caller. Response validation
// can prevent delivery but cannot undo an operation already executed by an origin.
package apipolicy

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path"
	"strings"
)

const MaxBytes = 1 << 20
const MaxNodes = 4096
const MaxDepth = 32

// Errors never include instance values, credentials, or schema diagnostics.
var ErrInvalid = errors.New("API policy validation failed")

type Artifact struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

// Declaration is the descriptorPath JSON document. Every external resource must
// be explicitly declared and SHA-256 pinned, including the FileDescriptorSet.
type Declaration struct {
	Version     string                  `json:"version"`
	Artifacts   map[string]Artifact     `json:"artifacts"`
	OpenAPI     string                  `json:"openapi,omitempty"`
	Descriptors string                  `json:"descriptors,omitempty"`
	GRPC        map[string]MethodPolicy `json:"grpc,omitempty"`
	Passthrough []Binding               `json:"passthrough,omitempty"`
}

type Binding struct {
	Method string `json:"method"`
	Path   string `json:"path"`
}

type Bundle struct {
	operations  []*Operation
	methods     map[string]*grpcMethod
	passthrough map[Binding]bool
}

func strict(data []byte, out any) error {
	if _, err := ParseJSON(data); err != nil {
		return err
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	d.DisallowUnknownFields()
	if err := d.Decode(out); err != nil {
		return ErrInvalid
	}
	return nil
}

func local(name string) bool {
	return name != "" && name != "." && path.Clean(name) == name && !strings.ContainsAny(name, "\\:#?%") && !strings.HasPrefix(name, "/") && name != ".." && !strings.HasPrefix(name, "../")
}

func readPinned(root *os.Root, name, digest string) ([]byte, error) {
	if !local(name) || len(digest) != 64 {
		return nil, ErrInvalid
	}
	want, err := hex.DecodeString(digest)
	if err != nil {
		return nil, ErrInvalid
	}
	f, err := root.Open(name)
	if err != nil {
		return nil, ErrInvalid
	}
	defer f.Close()
	stat, err := f.Stat()
	if err != nil || !stat.Mode().IsRegular() || stat.Size() > MaxBytes {
		return nil, ErrInvalid
	}
	data, err := io.ReadAll(io.LimitReader(f, MaxBytes+1))
	if err != nil || len(data) > MaxBytes {
		return nil, ErrInvalid
	}
	sum := sha256.Sum256(data)
	if !bytes.Equal(sum[:], want) {
		return nil, ErrInvalid
	}
	return data, nil
}

// Load confines all artifact opens (including symlink resolution) to bootstrapDir.
// The declaration itself is pinned by descriptorSHA256 in the WAF configuration.
func Load(bootstrapDir, descriptorPath, descriptorSHA256 string) (*Bundle, error) {
	root, err := os.OpenRoot(bootstrapDir)
	if err != nil {
		return nil, ErrInvalid
	}
	defer root.Close()
	data, err := readPinned(root, descriptorPath, descriptorSHA256)
	if err != nil {
		return nil, err
	}
	var d Declaration
	if err := strict(data, &d); err != nil {
		return nil, err
	}
	if d.Version != "netcap-api/v1" || len(d.Artifacts) > 16 || len(d.GRPC) > 128 || len(d.Passthrough) > 128 {
		return nil, ErrInvalid
	}
	resources := map[string]any{}
	raw := map[string][]byte{}
	total := 0
	for name, a := range d.Artifacts {
		if !local(name) {
			return nil, ErrInvalid
		}
		b, err := readPinned(root, a.Path, a.SHA256)
		if err != nil {
			return nil, err
		}
		total += len(b)
		if total > 4*MaxBytes {
			return nil, ErrInvalid
		}
		raw[name] = b
		if name != d.Descriptors {
			v, err := ParseJSON(b)
			if err != nil {
				return nil, err
			}
			resources[name] = v
		}
	}
	b := &Bundle{methods: map[string]*grpcMethod{}, passthrough: map[Binding]bool{}}
	for _, p := range d.Passthrough {
		if !validBinding(p) || b.passthrough[p] {
			return nil, ErrInvalid
		}
		b.passthrough[p] = true
	}
	if d.OpenAPI != "" {
		doc, ok := resources[d.OpenAPI]
		if !ok {
			return nil, ErrInvalid
		}
		budget := 16384
		doc, err = expand(doc, d.OpenAPI, resources, map[string]bool{}, 0, &budget)
		if err != nil {
			return nil, err
		}
		if err := b.compileOpenAPI(doc); err != nil {
			return nil, err
		}
	}
	if d.Descriptors != "" {
		if err := b.compileGRPC(raw[d.Descriptors], d.GRPC, resources); err != nil {
			return nil, err
		}
	} else if len(d.GRPC) != 0 {
		return nil, ErrInvalid
	}
	if len(b.operations)+len(b.methods)+len(b.passthrough) == 0 {
		return nil, ErrInvalid
	}
	return b, nil
}

func validBinding(b Binding) bool {
	return canonicalPath(b.Path) && !strings.ContainsAny(b.Path, "{}") && strings.Contains(" GET POST PUT PATCH DELETE HEAD OPTIONS TRACE ", " "+b.Method+" ")
}

func canonicalPath(p string) bool {
	if !strings.HasPrefix(p, "/") || len(p) > 2048 || strings.ContainsAny(p, "?#%\\\x00\r\n") || strings.Contains(p, "//") {
		return false
	}
	for _, s := range strings.Split(p, "/") {
		if s == "." || s == ".." {
			return false
		}
	}
	return true
}

// expand resolves only declared resources and RFC 6901 pointers. Cycles and
// exponential reference expansion fail at bootstrap, before invoking a compiler.
func expand(v any, resource string, docs map[string]any, stack map[string]bool, depth int, budget *int) (any, error) {
	*budget--
	if depth > MaxDepth || *budget < 0 {
		return nil, ErrInvalid
	}
	switch x := v.(type) {
	case map[string]any:
		if ref, ok := x["$ref"]; ok {
			r, ok := ref.(string)
			if !ok || len(x) != 1 {
				return nil, ErrInvalid
			}
			name, ptr, _ := strings.Cut(r, "#")
			if name == "" {
				name = resource
			}
			if !local(name) || (ptr != "" && !strings.HasPrefix(ptr, "/")) {
				return nil, ErrInvalid
			}
			key := name + "#" + ptr
			if stack[key] {
				return nil, ErrInvalid
			}
			target, ok := docs[name]
			if !ok {
				return nil, ErrInvalid
			}
			if ptr != "" {
				for _, part := range strings.Split(ptr[1:], "/") {
					part = strings.ReplaceAll(strings.ReplaceAll(part, "~1", "/"), "~0", "~")
					m, ok := target.(map[string]any)
					if !ok {
						return nil, ErrInvalid
					}
					target, ok = m[part]
					if !ok {
						return nil, ErrInvalid
					}
				}
			}
			stack[key] = true
			out, err := expand(target, name, docs, stack, depth+1, budget)
			delete(stack, key)
			return out, err
		}
		out := map[string]any{}
		for k, child := range x {
			// These values are instance data/annotations, not reference sites.
			if k == "const" || k == "enum" || k == "default" || k == "example" || k == "examples" {
				out[k] = child
				continue
			}
			var err error
			out[k], err = expand(child, resource, docs, stack, depth+1, budget)
			if err != nil {
				return nil, err
			}
		}
		return out, nil
	case []any:
		out := make([]any, len(x))
		for i, child := range x {
			var err error
			out[i], err = expand(child, resource, docs, stack, depth+1, budget)
			if err != nil {
				return nil, err
			}
		}
		return out, nil
	default:
		return v, nil
	}
}
