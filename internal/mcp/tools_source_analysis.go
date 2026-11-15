package mcp

import (
	"encoding/json"
	"fmt"

	"github.com/dreadl0ck/netcap/internal/protocoltest"
	mcplib "github.com/mark3labs/mcp-go/mcp"
)

type streamGrammarRequest struct {
	SessionID        string               `json:"session_id"`
	ID               string               `json:"id"`
	Direction        string               `json:"direction" jsonschema:"enum=client,enum=server"`
	ManifestSHA256   string               `json:"manifestSHA256"`
	CompareID        string               `json:"compareId,omitempty"`
	CompareDirection string               `json:"compareDirection,omitempty"`
	CompareManifest  string               `json:"compareManifestSHA256,omitempty"`
	Grammar          protocoltest.Grammar `json:"grammar"`
}
type tlsCaptureRequest struct {
	SessionID    string `json:"session_id"`
	KeyLog       string `json:"keyLog"`
	SourceSHA256 string `json:"sourceSHA256"`
	Stream       *int   `json:"stream,omitempty"`
	CommunityID  string `json:"communityId,omitempty"`
}

func (s *Server) sourceReportProjection(name string) func(json.RawMessage, mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
	return func(raw json.RawMessage, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
		var report struct {
			Report   json.RawMessage `json:"report"`
			Error    string          `json:"operation_error"`
			Manifest string          `json:"manifestSHA256"`
		}
		if err := json.Unmarshal(raw, &report); err != nil || len(report.Report) == 0 {
			return nil, fmt.Errorf("invalid source analysis response")
		}
		var err error
		if report.Error != "" {
			err = fmt.Errorf("%s", report.Error)
		}
		return s.operationResult(name, map[string]any{"analysis": report.Report, "manifestSHA256": report.Manifest}, err), nil
	}
}
func (s *Server) registerSourceAnalysisTools() error {
	for _, tool := range []apiTool{
		{name: "interpret_stream_grammar", path: "/api/investigation/interpret-stream", post: true, readOnlyPost: true, session: true, description: "Interpret or compare retained directional TCP bytes (at most 16 MiB each) under an explicit grammar. Requires the manifest SHA256 from get_stream_content; refuses gaps, discarded bytes and datagrams. Sources remain session-confined; large reports become bounded readable MCP artifacts.", options: []mcplib.ToolOption{wireInputSchema[streamGrammarRequest]()}, project: s.sourceReportProjection("stream-grammar")},
		{name: "analyze_tls_capture", path: "/api/investigation/tls-capture", post: true, readOnlyPost: true, session: true, description: "Analyze a registered PCAP/TLS stream using an explicitly supplied backend-local NSS keyLog and installed tshark. sourceSHA256 binds the capture; stream (default 0) and communityId are exclusive. Input and secrets are privately snapshotted; secret contents/paths are never included in output. Node ordering and completeness remain qualified. Service mode requires its existing administrator identity.", options: []mcplib.ToolOption{wireInputSchema[tlsCaptureRequest]()}, project: s.sourceReportProjection("tls-capture")},
	} {
		if err := s.registerAPITool(tool); err != nil {
			return err
		}
	}
	return nil
}
