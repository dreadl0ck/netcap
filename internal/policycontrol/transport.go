package policycontrol

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/dreadl0ck/netcap/internal/firewallauth"
	"github.com/dreadl0ck/netcap/internal/policy"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// Handler must be served on an administrative listener with TLS (or behind a
// trusted TLS terminator). All routes, including MCP initialization, require auth.
func (s *Service) Handler() http.Handler {
	mux := http.NewServeMux()
	if s.cfg.Auth != nil {
		mux.Handle("/api/v1/auth/", s.cfg.Auth.LifecycleHandler(s.cfg.Origin))
	}
	mux.Handle("/mcp", server.NewStreamableHTTPServer(s.mcp, server.WithStateLess(true), server.WithDisableStreaming(true)))
	for _, op := range []string{"capabilities", "revision", "revisions", "check", "evaluate", "stage", "diff", "activate", "rollback", "audit", "approval"} {
		mux.HandleFunc("/api/v1/policy/"+op, func(w http.ResponseWriter, r *http.Request) {
			operation := op
			if op == "revisions" && r.Method == http.MethodPost {
				operation = "stage"
			}
			read := operation == "capabilities" || operation == "revision" || operation == "revisions" || operation == "audit"
			if (read && r.Method != http.MethodGet) || (!read && r.Method != http.MethodPost) {
				if read {
					w.Header().Set("Allow", "GET")
				} else {
					w.Header().Set("Allow", "POST")
				}
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			var request Request
			if read {
				request.Revision = r.URL.Query().Get("revision")
				if limit := r.URL.Query().Get("limit"); limit != "" {
					var err error
					request.Limit, err = strconv.Atoi(limit)
					if err != nil {
						writeError(w, failure(400, "invalid audit limit"))
						return
					}
				}
			} else {
				raw, err := io.ReadAll(r.Body)
				if err != nil {
					writeError(w, failure(413, "request exceeds input limit"))
					return
				}
				if err := decodeRequest(raw, &request); err != nil {
					writeError(w, failure(400, "invalid JSON request"))
					return
				}
			}
			if key := r.Header.Get("Idempotency-Key"); key != "" {
				if request.IdempotencyKey != "" && request.IdempotencyKey != key {
					writeError(w, failure(400, "conflicting idempotency keys"))
					return
				}
				request.IdempotencyKey = key
			}
			result, err := s.Execute(r.Context(), operation, request)
			if err != nil {
				writeError(w, err)
				return
			}
			writeJSON(w, http.StatusOK, result)
		})
	}
	want := sha256.Sum256([]byte(s.cfg.Token))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		auth := r.Header.Get("Authorization")
		got := sha256.Sum256([]byte(strings.TrimPrefix(auth, "Bearer ")))
		valid := strings.HasPrefix(auth, "Bearer ") && subtle.ConstantTimeCompare(got[:], want[:]) == 1
		if s.cfg.Auth != nil {
			var err error
			r, err = s.cfg.Auth.Request(r)
			valid = err == nil
		}
		if !valid {
			w.Header().Set("WWW-Authenticate", `Bearer realm="policycontrol"`)
			writeError(w, failure(401, "administrative bearer token required"))
			return
		}
		// A bootstrap-configured exact origin is allowed without enabling CORS.
		if !firewallauth.AllowOrigin(r, s.cfg.Origin) {
			writeError(w, failure(403, "browser origins are not supported"))
			return
		}
		select {
		case s.httpSlots <- struct{}{}:
			defer func() { <-s.httpSlots }()
		default:
			writeError(w, failure(429, "administrative concurrency limit reached"))
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
		defer cancel()
		r = r.WithContext(ctx)
		r.Body = http.MaxBytesReader(w, r.Body, MaxInputBytes)
		if r.URL.Path == "/mcp" {
			if version := r.Header.Get("MCP-Protocol-Version"); version != "" && !slices.Contains(mcp.ValidProtocolVersions, version) {
				writeError(w, failure(400, "unsupported MCP protocol version"))
				return
			}
			if r.Method == http.MethodPost {
				raw, err := io.ReadAll(r.Body)
				if err != nil {
					writeError(w, failure(413, "request exceeds input limit"))
					return
				}
				if err = uniqueJSON(raw); err != nil {
					writeError(w, failure(400, "invalid or duplicate JSON keys"))
					return
				}
				r.Body = io.NopCloser(bytes.NewReader(raw))
			}
		}
		mux.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	data, err := json.Marshal(value)
	if err != nil || len(data) > 1<<20 {
		http.Error(w, "response exceeds administrative limit", 500)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(data)
}

func publicError(err error) (int, string) {
	var api *apiError
	if errors.As(err, &api) {
		return api.status, api.message
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return 408, "administrative request cancelled"
	}
	return 500, "policy operation failed"
}
func writeError(w http.ResponseWriter, err error) {
	code, message := publicError(err)
	writeJSON(w, code, map[string]string{"error": message})
}

func (s *Service) newMCP() *server.MCPServer {
	srv := server.NewMCPServer("netcap-policycontrol", "1.0.0", server.WithToolCapabilities(false))
	if s.cfg.Auth != nil {
		s.cfg.Auth.AddLifecycleTool(srv)
	}
	for _, spec := range []struct {
		name, op, description string
		fields                []string
	}{
		{"issue_policy_approval", "approval", "Issue a five-minute server-signed receipt for a separate authorized principal and exact request digest.", []string{"approval"}},
		{"get_policy_capabilities", "capabilities", "Read mode, single-target scope, and limits.", nil},
		{"get_policy_revision", "revision", "Read an immutable revision; empty revision selects active.", []string{"revision"}},
		{"check_policy_bundle", "check", "Parse and compile a bundle without staging or target mutation.", []string{"bundle"}},
		{"stage_policy_revision", "stage", "Validate and retain an immutable bundle in managed mode.", []string{"bundle", "idempotency_key"}},
		{"diff_policy_revisions", "diff", "Compare retained revisions; returns changed top-level fields.", []string{"revision", "other_revision"}},
		{"explain_policy_decision", "evaluate", "Replay synthetic events with isolated per-replay state; no network or target mutation. Use event or events.", []string{"revision", "event", "events"}},
		{"activate_policy_deployment", "activate", "Activate a staged revision using expected_revision CAS and idempotency_key.", []string{"revision", "expected_revision", "idempotency_key", "receipt"}},
		{"rollback_policy_deployment", "rollback", "Activate a retained revision, or previous if omitted, using CAS and idempotency_key.", []string{"revision", "expected_revision", "idempotency_key", "receipt"}},
		{"query_policy_audit", "audit", "Query bounded successful mutation audit records.", []string{"limit"}},
	} {
		if spec.op == "approval" && s.cfg.Approvals == nil {
			continue
		}
		op := spec.op
		mutation := op == "stage" || op == "activate" || op == "rollback" || op == "approval"
		opts := []mcp.ToolOption{mcp.WithDescription(spec.description), mcp.WithReadOnlyHintAnnotation(!mutation), mcp.WithOpenWorldHintAnnotation(false)}
		for _, field := range spec.fields {
			switch field {
			case "approval":
				schema := jsonSchema(reflect.TypeOf(firewallauth.ApprovalRequest{}))
				opts = append(opts, mcp.WithObject(field, mcp.Properties(schema["properties"].(map[string]any)), mcp.AdditionalProperties(false), mcp.Required()))
			case "event", "events":
				schema := jsonSchema(reflect.TypeOf(policy.Event{}))
				if field == "events" {
					opts = append(opts, mcp.WithArray(field, mcp.Items(schema), mcp.MaxItems(MaxEvents)))
				} else {
					opts = append(opts, mcp.WithObject(field, mcp.Properties(schema["properties"].(map[string]any)), mcp.AdditionalProperties(false)))
				}
			case "limit":
				opts = append(opts, mcp.WithNumber(field, mcp.Description("Maximum audit rows (1..2048, default 100).")))
			default:
				required := field == "bundle" || field == "idempotency_key" || field == "expected_revision" || (field == "revision" && (op == "activate" || op == "diff")) || field == "other_revision"
				if required {
					opts = append(opts, mcp.WithString(field, mcp.Required()))
				} else {
					opts = append(opts, mcp.WithString(field))
				}
			}
		}
		srv.AddTool(mcp.NewTool(spec.name, opts...), func(ctx context.Context, call mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			raw, err := json.Marshal(call.Params.Arguments)
			if err != nil || len(raw) > MaxInputBytes {
				return mcp.NewToolResultError("request exceeds input limit"), nil
			}
			var request Request
			if err = decodeRequest(raw, &request); err != nil {
				return mcp.NewToolResultError("invalid policy arguments"), nil
			}
			result, err := s.Execute(ctx, op, request)
			if err != nil {
				_, message := publicError(err)
				return mcp.NewToolResultError(message), nil
			}
			encoded, err := json.Marshal(result)
			if err != nil || len(encoded) > 1<<20 {
				return mcp.NewToolResultError("response exceeds administrative limit"), nil
			}
			return mcp.NewToolResultText(string(encoded)), nil
		})
	}
	return srv
}

// ServeStdio requires explicit local grants, including in legacy bearer mode.
func (s *Service) ServeStdio(ctx context.Context) error {
	if s.cfg.StdioPrincipal == nil {
		return errors.New("explicit stdio principal required")
	}
	ctx = firewallauth.WithPrincipal(ctx, *s.cfg.StdioPrincipal)
	return server.NewStdioServer(s.mcp).Listen(ctx, &lineLimitReader{reader: os.Stdin}, os.Stdout)
}

// Limit every JSON-RPC line before mcp-go's buffered reader can accumulate it.
type lineLimitReader struct {
	reader io.Reader
	count  int
	line   []byte
}

func (r *lineLimitReader) Read(p []byte) (int, error) {
	n, err := r.reader.Read(p)
	for _, b := range p[:n] {
		if b == '\n' {
			if len(bytes.TrimSpace(r.line)) > 0 {
				if err := uniqueJSON(r.line); err != nil {
					return 0, err
				}
			}
			r.line = r.line[:0]
			r.count = 0
		} else {
			r.count++
			r.line = append(r.line, b)
		}
		if r.count > MaxInputBytes {
			return 0, errors.New("MCP input line exceeds limit")
		}
	}
	if err == io.EOF && len(bytes.TrimSpace(r.line)) > 0 {
		if e := uniqueJSON(r.line); e != nil {
			return 0, e
		}
	}
	return n, err
}
