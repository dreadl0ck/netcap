package mcp

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"strings"
	"time"

	"github.com/dreadl0ck/netcap/internal/analyst"
	"github.com/dreadl0ck/netcap/internal/protocoltest"
	mcplib "github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

func localOperation[T any](s *Server, name, description string, network bool, run func(context.Context, T) (any, error)) error {
	return s.registerAPITool(apiTool{name: name, post: true, readOnlyPost: !network, openWorld: network, description: description, options: []mcplib.ToolOption{wireInputSchema[T]()}, run: func(ctx context.Context, data json.RawMessage) (any, error) {
		var request T
		if err := analyst.DecodeStrict(data, &request); err != nil {
			return nil, err
		}
		if err := validateProtocolFiles(reflect.ValueOf(request)); err != nil {
			return nil, err
		}
		if network && !s.networkAllowed {
			return nil, fmt.Errorf("outbound protocol experiments are disabled by the existing network policy; net mcp --allow-fetch enables network tools")
		}
		ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
		defer cancel()
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		return run(ctx, request)
	}})
}

func validateProtocolFiles(value reflect.Value) error {
	if value.Kind() == reflect.Pointer {
		if value.IsNil() {
			return nil
		}
		return validateProtocolFiles(value.Elem())
	}
	if value.Kind() == reflect.Struct {
		for i := 0; i < value.NumField(); i++ {
			field := value.Type().Field(i)
			item := value.Field(i)
			if item.Kind() == reflect.String && strings.HasSuffix(field.Name, "File") && item.String() != "" {
				info, err := os.Stat(item.String())
				if err != nil || !info.Mode().IsRegular() || info.Size() > 4<<20 {
					return fmt.Errorf("TLS credential/trust files must be regular and at most 4 MiB")
				}
			}
			if err := validateProtocolFiles(item); err != nil {
				return err
			}
		}
	}
	if value.Kind() == reflect.Slice && value.Type().Elem().Kind() != reflect.Uint8 {
		for i := 0; i < value.Len(); i++ {
			if err := validateProtocolFiles(value.Index(i)); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *Server) operationResult(name string, value any, err error) *mcplib.CallToolResult {
	if value == nil && err != nil {
		return errResult(err)
	}
	result := map[string]any{"report": value}
	if err != nil {
		result["operation_error"] = err.Error()
	}
	raw, encodeErr := json.Marshal(result)
	if encodeErr != nil {
		return errResult(encodeErr)
	}
	var output *mcplib.CallToolResult
	if len(raw) <= MaxResponseBytes {
		output = rawJSONResult(raw)
	} else {
		if len(raw) > MaxCarveBytes {
			return errResult(fmt.Errorf("operation report exceeds 16 MiB; narrow input/case budgets"))
		}
		entry, uri, storeErr := s.carve.PutTyped("", name, "local bounded operation", "application/json", raw)
		if storeErr != nil {
			return errResult(storeErr)
		}
		output = jsonResult(map[string]any{"artifact_id": entry.ID, "resource_uri": uri, "sha256": entry.SHA256, "size_bytes": entry.SizeBytes, "content_type": entry.MIMEType, "next_step": "Read bounded pages with read_mcp_artifact; report contains exact observations and limitations."})
	}
	if err != nil {
		output.IsError = true
	}
	return output
}

type grammarRequest struct {
	Grammar protocoltest.Grammar `json:"grammar"`
	Data    []byte               `json:"data"`
	Compare []byte               `json:"compare,omitempty"`
}
type corpusRequest struct {
	Data          []byte `json:"data"`
	MaxCases      int    `json:"maxCases"`
	MaxBytes      int    `json:"maxBytes"`
	TargetVersion string `json:"targetVersion"`
}
type accessRequest struct {
	Cases []protocoltest.AccessCase `json:"cases"`
}
type triageRequest struct {
	Kind          string `json:"kind"`
	TargetVersion string `json:"targetVersion"`
	Reset         string `json:"reset"`
	Generation    string `json:"generation"`
	Data          []byte `json:"data"`
	Artifact      string `json:"artifact"`
}

func (s *Server) registerExperimentTools() error {
	for _, register := range []func() error{
		func() error {
			return localOperation(s, "interpret_protocol_grammar", "Interpret a bounded directional byte sequence using explicit framing/field/TLV hypotheses; optional compare returns differences. data/compare are base64. Parsing is not proof of protocol semantics; retain stream loss qualifications.", false, func(ctx context.Context, r grammarRequest) (any, error) {
				if r.Compare != nil {
					return r.Grammar.Compare(r.Data, r.Compare)
				}
				return r.Grammar.Interpret(r.Data)
			})
		},
		func() error {
			return localOperation(s, "generate_protocol_cases", "Generate deterministic grammar/field/setup-step campaign cases offline, preserving control, configuration hashes and target/reset declarations. No packets are sent.", false, func(ctx context.Context, r protocoltest.Campaign) (any, error) {
				return protocoltest.GenerateCampaign(r)
			})
		},
		func() error {
			return localOperation(s, "generate_protocol_corpus", "Generate versioned control/truncation/XOR byte cases offline. data is base64; explicit maxCases/maxBytes bound output.", false, func(ctx context.Context, r corpusRequest) (any, error) {
				return protocoltest.GenerateByteCorpus(r.Data, r.MaxCases, r.MaxBytes, r.TargetVersion)
			})
		},
		func() error {
			return localOperation(s, "run_protocol_exchange", "Run one bounded TCP/UDP/TLS exchange with framing, response assertions, fresh variables and exact byte/hash observations. Byte fields are base64. Uses existing network policy; no shell commands or automatic interpretation of payload instructions.", true, func(ctx context.Context, r protocoltest.Exchange) (any, error) { return protocoltest.Run(ctx, r) })
		},
		func() error {
			return localOperation(s, "run_protocol_campaign", "Run bounded deterministic mutations and minimization with valid pre/post controls, explicit reset isolation and response marker oracle. Timeout/crash is not RCE; partial failures remain report errors.", true, func(ctx context.Context, r protocoltest.Campaign) (any, error) {
				return protocoltest.RunCampaign(ctx, r)
			})
		},
		func() error {
			return localOperation(s, "run_protocol_access_matrix", "Run labeled state/role/resource cases with a new session and declared reset per case. Missing markers are meaningful only after response assertions match; transport failures stay inconclusive.", true, func(ctx context.Context, r accessRequest) (any, error) { return protocoltest.RunAccess(ctx, r.Cases) })
		},
		func() error {
			return localOperation(s, "run_protocol_boundary", "Compare valid control/probe/readback across a semantic boundary using exact accepted/rejected replies; preserve harness-error and qualification states.", true, func(ctx context.Context, r protocoltest.BoundaryCase) (any, error) {
				return protocoltest.RunBoundary(ctx, r)
			})
		},
		func() error {
			return localOperation(s, "reproduce_protocol_case", "Verify generated case hash, perform declared reset and rerun its exact exchange against the explicit marker oracle.", true, func(ctx context.Context, r protocoltest.ReproductionSpec) (any, error) {
				return protocoltest.Reproduce(ctx, r)
			})
		},
		func() error {
			return localOperation(s, "import_protocol_triage", "Import explicitly labeled external crash/sanitizer evidence verbatim with generation, target and reset declarations. No execution or inferred RCE.", false, func(ctx context.Context, r triageRequest) (any, error) {
				return protocoltest.ImportGeneratedTriage(r.Kind, r.TargetVersion, r.Reset, r.Generation, r.Data, r.Artifact)
			})
		},
	} {
		if err := register(); err != nil {
			return err
		}
	}
	return s.addTool(server.ServerTool{Tool: mcplib.NewTool("read_mcp_artifact", mcplib.WithDescription("Read a bounded base64 page of a retained MCP artifact/report/evidence ZIP. Use artifact_id, or the final id segment of netcap://carve/{id}. Session-derived artifacts require the original session_id. TTL 1h, store capacity 32; content type and SHA256 identify the complete artifact."), mcplib.WithString("artifact_id", mcplib.Required()), mcplib.WithString("session_id"), apiInteger("offset", "Byte offset.", 0, 16777216, false), apiInteger("limit", "Page bytes, default 16384.", 1, 65536, false), mcplib.WithReadOnlyHintAnnotation(true)), Handler: func(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
		id := req.GetString("artifact_id", "")
		if len(id) != 32 || !isHex(id) {
			return errResult(fmt.Errorf("invalid artifact id")), nil
		}
		offset, err := pageInteger(req, "offset", 0, 0, 16777216)
		if err != nil {
			return errResult(err), nil
		}
		limit, err := pageInteger(req, "limit", 16384, 1, 65536)
		if err != nil {
			return errResult(err), nil
		}
		entry, err := s.carve.page(id, strings.TrimSpace(req.GetString("session_id", "")), offset, limit)
		if err != nil {
			return errResult(err), nil
		}
		return jsonResult(map[string]any{"artifact_id": id, "sha256": entry.SHA256, "content_type": entry.MIMEType, "offset": offset, "total_bytes": entry.SizeBytes, "data": base64.StdEncoding.EncodeToString(entry.Bytes), "encoding": "base64", "has_more": int64(offset+len(entry.Bytes)) < entry.SizeBytes}), nil
	}})
}
