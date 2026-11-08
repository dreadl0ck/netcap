// Package firewallaudit projects decoder records into retrospective policy events.
// It does not intercept the transaction that produced a record.
package firewallaudit

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"

	_ "github.com/dreadl0ck/netcap/types" // register the compiled descriptor, not arbitrary messages
	"github.com/gogo/protobuf/proto"
	"github.com/gogo/protobuf/protoc-gen-gogo/descriptor"
)

const (
	MaxFields     = 128
	MaxValueBytes = 1024
	MaxItems      = 4
	MaxDepth      = 6
	MaxNodes      = 4096
)

type Field struct {
	Path        string `json:"path"`
	Type        string `json:"type"`
	Sensitivity string `json:"sensitivity"`
}

type Schema struct {
	RecordType string  `json:"record_type"`
	Fields     []Field `json:"fields"`
}

// Capabilities describes the exact compiled protobuf surface. All values are
// transient, including secret fields; audit output never contains field values.
type Capabilities struct {
	Version         string   `json:"version"`
	Protocol        string   `json:"protocol"`
	Phase           string   `json:"phase"`
	EvaluationPhase string   `json:"evaluation_phase"`
	Attributes      []string `json:"attributes"`
	MaxFields       int      `json:"max_fields"`
	MaxValueBytes   int      `json:"max_value_bytes"`
	MaxItems        int      `json:"max_items"`
	MaxDepth        int      `json:"max_depth"`
	MaxNodes        int      `json:"max_nodes"`
	Collections     string   `json:"collections"`
	Omissions       string   `json:"omissions"`
	Records         []Schema `json:"records"`
}

var registryOnce sync.Once
var capabilities Capabilities
var recordTypes map[reflect.Type]Schema
var recordFields map[reflect.Type]map[string]bool

// Discover returns an independent copy suitable for agent/tool discovery.
func Discover() Capabilities {
	registryOnce.Do(initRegistry)
	c := capabilities
	c.Attributes = append([]string(nil), capabilities.Attributes...)
	c.Records = make([]Schema, len(capabilities.Records))
	for i, s := range capabilities.Records {
		c.Records[i] = Schema{s.RecordType, append([]Field(nil), s.Fields...)}
	}
	return c
}

func initRegistry() {
	recordTypes = make(map[reflect.Type]Schema)
	recordFields = make(map[reflect.Type]map[string]bool)
	capabilities = Capabilities{Protocol: "audit", Phase: "retrospective", MaxFields: MaxFields, MaxValueBytes: MaxValueBytes, MaxItems: MaxItems, MaxDepth: MaxDepth, MaxNodes: MaxNodes,
		EvaluationPhase: "request", Attributes: []string{"audit.schema_version", "audit.truncated"},
		Collections: "Go field names; nested A.B; arrays A[0]..A[3], A.Length; maps A[0].Key/A[0].Value sorted by scalar key, A.Length; maps larger than max_items omit all entries; bytes lowercase hex",
		Omissions:   "nil/absent nested fields omitted; oversized scalars omitted, never clipped; declaration-order traversal; excess fields/depth/work omitted; projection reports truncated"}
	gz, err := gzip.NewReader(bytes.NewReader(proto.FileDescriptor("netcap.proto")))
	if err != nil {
		panic("firewallaudit: compiled descriptor unavailable")
	}
	rawDescriptor, err := io.ReadAll(io.LimitReader(gz, 4<<20))
	_ = gz.Close()
	var file descriptor.FileDescriptorProto
	if err != nil || proto.Unmarshal(rawDescriptor, &file) != nil {
		panic("firewallaudit: invalid compiled descriptor")
	}
	for _, message := range file.MessageType {
		t := proto.MessageType(file.GetPackage() + "." + message.GetName())
		if t == nil || t.Kind() != reflect.Ptr {
			continue
		}
		if _, exists := recordTypes[t]; exists {
			continue
		}
		s := Schema{RecordType: t.Elem().Name()}
		nodes := 0
		walkSchema(t, "", 0, &nodes, &s.Fields)
		recordTypes[t] = s
		keys := make(map[string]bool, len(s.Fields))
		for _, f := range s.Fields {
			keys[f.Path] = true
		}
		recordFields[t] = keys
		capabilities.Records = append(capabilities.Records, s)
	}
	sort.Slice(capabilities.Records, func(i, j int) bool { return capabilities.Records[i].RecordType < capabilities.Records[j].RecordType })
	raw, _ := json.Marshal(capabilities)
	h := sha256.Sum256(raw)
	capabilities.Version = "netcap-audit/v1:" + hex.EncodeToString(h[:])
}

func scalarType(t reflect.Type) string {
	switch t.Kind() {
	case reflect.String:
		return "string"
	case reflect.Bool:
		return "bool"
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return "int"
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return "uint"
	case reflect.Float32, reflect.Float64:
		return "float"
	case reflect.Slice:
		if t.Elem().Kind() == reflect.Uint8 {
			return "bytes-hex"
		}
	}
	return ""
}

func sensitivity(path, kind string) string {
	p := strings.ToLower(path)
	for _, token := range []string{"password", "secret", "credential", "authorization", "cookie", "token", "privatekey"} {
		if strings.Contains(p, token) {
			return "secret"
		}
	}
	if kind == "string" || kind == "bytes-hex" {
		return "sensitive"
	}
	return "metadata"
}

func join(prefix, name string) string {
	if prefix == "" {
		return name
	}
	return prefix + "." + name
}

func walkSchema(t reflect.Type, path string, depth int, nodes *int, fields *[]Field) {
	if depth > MaxDepth || *nodes >= MaxNodes || len(path) > 128 {
		return
	}
	*nodes++
	if t.Kind() == reflect.Ptr {
		t = t.Elem()
	}
	if kind := scalarType(t); kind != "" {
		*fields = append(*fields, Field{path, kind, sensitivity(path, kind)})
		return
	}
	switch t.Kind() {
	case reflect.Struct:
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			if f.Tag.Get("protobuf") != "" {
				walkSchema(f.Type, join(path, f.Name), depth+1, nodes, fields)
			}
		}
	case reflect.Slice, reflect.Array, reflect.Map:
		*fields = append(*fields, Field{path + ".Length", "int", "metadata"})
		for i := 0; i < MaxItems; i++ {
			p := path + "[" + strconv.Itoa(i) + "]"
			if t.Kind() == reflect.Map {
				walkSchema(t.Key(), p+".Key", depth+1, nodes, fields)
				walkSchema(t.Elem(), p+".Value", depth+1, nodes, fields)
			} else {
				walkSchema(t.Elem(), p, depth+1, nodes, fields)
			}
		}
	}
}
