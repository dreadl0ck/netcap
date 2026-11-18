package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	mcplib "github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

// apiTool only targets fixed backend contracts. Session selectors are translated
// separately so callers cannot override the registered dataset boundary.
type apiTool struct {
	name, path, description    string
	post, session, bodySession bool
	destructive                bool
	readOnlyPost               bool
	openWorld                  bool
	binary                     bool
	options                    []mcplib.ToolOption
	localArguments             []string
	project                    func(json.RawMessage, mcplib.CallToolRequest) (*mcplib.CallToolResult, error)
	run                        func(context.Context, json.RawMessage) (any, error)
}

func (s *Server) registerAPITool(spec apiTool) error {
	opts := append([]mcplib.ToolOption{mcplib.WithDescription(spec.description), mcplib.WithReadOnlyHintAnnotation(!spec.post || spec.readOnlyPost), mcplib.WithDestructiveHintAnnotation(spec.destructive), mcplib.WithOpenWorldHintAnnotation(spec.openWorld)}, spec.options...)
	if spec.session {
		opts = append(opts, mcplib.WithString("session_id", mcplib.Required(), mcplib.Description("Explicit session identifier returned by ingest_pcap or list_sessions.")))
	}
	tool := mcplib.NewTool(spec.name, opts...)
	encoded, err := json.Marshal(tool.InputSchema)
	if len(tool.RawInputSchema) > 0 {
		encoded = tool.RawInputSchema
	}
	if err != nil {
		return err
	}
	var schema map[string]any
	if err := json.Unmarshal(encoded, &schema); err != nil {
		return err
	}
	schema["additionalProperties"] = false
	if properties, ok := schema["properties"].(map[string]any); ok {
		if version, ok := properties["version"].(map[string]any); ok {
			// JSON-RPC argument maps may use float64; never round a CAS token.
			version["maximum"] = float64(9007199254740991)
		}
	}
	compiler := jsonschema.NewCompiler()
	if err := compiler.AddResource("urn:netcap:"+spec.name, schema); err != nil {
		return err
	}
	validated, err := compiler.Compile("urn:netcap:" + spec.name)
	if err != nil {
		return fmt.Errorf("schema %s: %w", spec.name, err)
	}
	tool.RawInputSchema, err = json.Marshal(schema)
	if err != nil {
		return err
	}
	tool.InputSchema = mcplib.ToolInputSchema{}
	return s.addTool(server.ServerTool{Tool: tool, Handler: func(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
		data, err := json.Marshal(req.GetArguments())
		if err != nil || len(data) > MaxResponseBytes {
			return errResult(fmt.Errorf("request exceeds 256 KiB or is invalid JSON")), nil
		}
		var body map[string]any
		if err := json.Unmarshal(data, &body); err != nil {
			return errResult(err), nil
		}
		if body == nil {
			body = map[string]any{}
		}
		if err := validated.Validate(body); err != nil {
			return errResult(fmt.Errorf("invalid %s arguments: %w", spec.name, err)), nil
		}
		if spec.run != nil {
			value, runErr := spec.run(ctx, data)
			return s.operationResult(spec.name, value, runErr), nil
		}
		q := url.Values{}
		sessionID := ""
		if spec.session {
			if strings.TrimSpace(req.GetString("session_id", "")) == "" {
				return errResult(fmt.Errorf("explicit session_id is required")), nil
			}
			ref, err := s.requireSessionID(req)
			if err != nil || ref.ID == "" {
				return errResult(fmt.Errorf("explicit session_id is required")), nil
			}
			q = ref.sessionQueryParams()
			sessionID = ref.ID
			delete(body, "session_id")
			if spec.bodySession {
				if ref.isPath {
					body["inputFile"] = ref.ID
				} else {
					body["sessionId"] = ref.ID
				}
				q = nil
			}
		}
		client := s.newClient()
		for _, name := range spec.localArguments {
			delete(body, name)
		}
		var raw json.RawMessage
		if spec.post {
			path := spec.path
			if len(q) > 0 {
				path += "?" + q.Encode()
			}
			raw, err = client.PostJSONContext(ctx, path, body)
		} else {
			for key, value := range body {
				switch v := value.(type) {
				case string:
					q.Set(key, v)
				case float64:
					q.Set(key, strconv.FormatFloat(v, 'f', -1, 64))
				case bool:
					q.Set(key, strconv.FormatBool(v))
				}
			}
			if spec.binary {
				data, mime, err := client.GetRawContext(ctx, spec.path, q)
				if err != nil {
					return errResult(err), nil
				}
				if mime != "application/zip" {
					return errResult(fmt.Errorf("packet evidence endpoint returned unexpected content type %q", mime)), nil
				}
				entry, uri, err := s.carve.PutTyped(sessionID, spec.name, client.BaseURL()+spec.path+"?"+q.Encode(), mime, data)
				if err != nil {
					return errResult(err), nil
				}
				return jsonResult(map[string]any{"artifact_id": entry.ID, "resource_uri": uri, "sha256": entry.SHA256, "size_bytes": entry.SizeBytes, "content_type": mime, "selection": q, "limitations": []string{"One original source or one explicitly retained segment; expired segments and broader capture completeness are not inferred"}}), nil
			}
			raw, err = client.GetContext(ctx, spec.path, q)
		}
		if err != nil {
			return errResult(err), nil
		}
		if !json.Valid(raw) {
			return errResult(fmt.Errorf("backend %s returned invalid JSON", spec.path)), nil
		}
		if spec.project != nil {
			result, err := spec.project(raw, req)
			if err != nil {
				return errResult(err), nil
			}
			return result, nil
		}
		if spec.name == "get_capture_evidence" {
			record, err := s.completeRecordJSON(newSessionRef(sessionID), spec.name, raw)
			if err != nil {
				return errResult(err), nil
			}
			return rawJSONResult(record), nil
		}
		return rawJSONResult(raw), nil
	}})
}

func apiString(name, description string, required bool, values ...string) mcplib.ToolOption {
	opts := []mcplib.PropertyOption{mcplib.Description(description)}
	if required {
		opts = append(opts, mcplib.Required())
	}
	if len(values) > 0 {
		opts = append(opts, mcplib.Enum(values...))
	}
	return mcplib.WithString(name, opts...)
}

func apiInteger(name, description string, min, max float64, required bool) mcplib.ToolOption {
	opts := []mcplib.PropertyOption{mcplib.Description(description), mcplib.Min(min), mcplib.Max(max), mcplib.MultipleOf(1)}
	if required {
		opts = append(opts, mcplib.Required())
	}
	return mcplib.WithNumber(name, opts...)
}

func (s *Server) registerCapabilityTools() error {
	tools := []apiTool{
		{name: "export_packet_evidence", path: "/api/investigation/packet-export", session: true, binary: true, description: "Export a bounded BPF/time selection from the bound original PCAP or one explicitly retained live segment as a provenance ZIP. Requires runId and sourceSHA256 from get_capture_evidence; for live traffic select a retained segment name and its SHA256. Active/expired/changed segments fail. Source cap 256 MiB, ZIP cap 16 MiB; narrow BPF/time/maxPackets rather than accepting silent truncation. Read returned artifact with read_mcp_artifact.", options: []mcplib.ToolOption{apiString("runId", "Expected capture run id.", true), apiString("sourceSHA256", "Original input hash, or selected retained segment hash.", true), apiString("segment", "Optional exact retained segment name from capture manifest.", false), apiString("bpf", "BPF selection, default all packets.", false), apiString("startNs", "Inclusive exact capture-time nanoseconds; paired with endNs.", false), apiString("endNs", "Inclusive exact capture-time nanoseconds; paired with startNs.", false), apiInteger("maxPackets", "Selected packet limit, default 1000000; overflow is an error.", 1, 1000000, false)}},
		{name: "get_analysis_settings", path: "/api/analysis/settings", description: "Discover actual future-analysis DPI support/module selection, payload capture, bounded retention/state budgets, incremental HTTP, capture-time expiry and flow-export configuration. Scope is process-wide; existing results are unchanged."},
		{name: "set_analysis_settings", path: "/api/analysis/settings", post: true, description: "Patch actual future-analysis settings without resetting omitted fields. False and empty CSV values are honored; null/unknown settings are rejected. Changes reach subsequent helper jobs and retained child reanalysis. Component limits exclude RSS; unavailable DPI cannot be enabled. Read get_analysis_settings first.", options: []mcplib.ToolOption{mcplib.WithBoolean("dpi"), apiString("dpiModules", "CSV go,ndpi,lpi; empty selects defaults.", false), mcplib.WithBoolean("payload"), mcplib.WithBoolean("retainPackets"), apiInteger("segmentMB", "Packet segment MiB.", 1, 1024, false), apiInteger("retentionMB", "Packet budget MiB; at least one segment.", 1, 16384, false), apiInteger("maxTCPBytes", "Copied TCP payload budget across workers.", 1, 1073741824, false), apiInteger("maxReassemblyBytes", "Aggregate reassembly page budget.", 1, 4294967296, false), apiInteger("maxTCPStateBytes", "TCP parser state budget.", 1, 1073741824, false), apiInteger("maxAggregateStateBytes", "Aggregate state budget.", 1, 1073741824, false), mcplib.WithBoolean("incrementalHTTP"), mcplib.WithBoolean("captureTimeIdleExpiry"), mcplib.WithBoolean("flowExports"), apiString("flowExportPorts", "Observed UDP port CSV; empty selects defaults.", false)}},
		{name: "get_stream_content", path: "/api/investigation/stream-content", session: true, description: "Read a verified directional stream page as base64, retaining manifest hash, status, loss limitations and a bounded span page (timestamps, gaps, datagram boundaries). Nonzero byte or span offsets require manifestSHA256 from the first response. No execution or complete-coverage claim is inferred.", options: []mcplib.ToolOption{apiString("id", "stream-* id from get_stream_evidence.", true), apiString("direction", "Direction.", true, "client", "server"), apiInteger("offset", "Byte offset.", 0, 268435456, false), apiInteger("limit", "Bytes per page, default 65536.", 1, 65536, false), apiInteger("spanOffset", "Manifest span offset.", 0, 1000000, false), apiInteger("spanLimit", "Manifest spans per page, default 64.", 1, 128, false), apiString("manifestSHA256", "Required on subsequent pages.", false)}},
		{name: "list_network_interfaces", path: "/api/network-interfaces", description: "Discover host interfaces before start_live_capture. No session is required; NC_LIVE_INTERFACES constrains capture admission when configured."},
		{name: "start_live_capture", path: "/api/live-capture", post: true, description: "Start one owned bounded local-host capture. Requires an existing interface, durationSeconds 1..300, retentionMB 1..512. Returns session_id; poll get_live_capture_status and stop_live_capture with that ID. Promiscuous mode is disabled. Hosted service mode cannot mix host traffic into tenant captures.", options: []mcplib.ToolOption{apiString("interface", "Interface from list_network_interfaces.", true), apiString("bpf", "Optional BPF.", false), apiInteger("durationSeconds", "Maximum duration.", 1, 300, true), apiInteger("retentionMB", "Rotating packet disk budget in MiB; additional audit output has a maintenance-time guard.", 1, 512, true)}},
		{name: "list_auth_activity", path: "/api/auth-activity", session: true, description: "Read authentication observations from the explicitly selected capture, including TACACS+, Kerberos and credential-capture evidence.", options: []mcplib.ToolOption{apiInteger("limit", "Events per page.", 1, 500, false), apiInteger("offset", "Event offset.", 0, 100000, false)}},
		{name: "get_features", path: "/api/features", description: "Discover optional features, enabled state, startup flags and whether changes affect queries or future captures."},
		{name: "set_feature", path: "/api/features", post: true, description: "Toggle one process-wide optional feature. evidence-links applies to the next query; capture-scoped changes reach subsequent in-process and helper analyses, including child reanalysis. Existing results remain unchanged. Read get_features first.", options: []mcplib.ToolOption{apiString("name", "Feature name.", true, "network-detection", "evidence-links", "dns-resolution-context"), mcplib.WithBoolean("enabled", mcplib.Required())}},
		{name: "get_analysis_config", path: "/api/config", session: true, description: "Read configuration for an explicitly selected capture without changing global selection. get_capture_evidence supplies the retained producer's effective settings and provenance."},
		{name: "get_bpf_config", path: "/api/config/bpf", description: "Read the persisted BPF filter and syntax examples used for future analyses."},
		{name: "set_bpf_config", path: "/api/config/bpf", post: true, description: "Validate and persist a process-wide BPF filter for future analyses (including child reanalysis). Empty filter clears it; does not change existing results.", options: []mcplib.ToolOption{apiString("filter", "BPF expression, or empty to clear.", true)}},
		{name: "get_decoder_config", path: "/api/decoders/config", description: "Read the persisted decoder selection for future analyses."},
		{name: "set_decoder_config", path: "/api/decoders/config", post: true, description: "Replace process-wide decoder selection for future analyses. Supply both includeDecoders and excludeDecoders (CSV); empty strings reset to all. Discover valid names with list_decoders.", options: []mcplib.ToolOption{apiString("includeDecoders", "Exclusive decoder CSV, or empty.", true), apiString("excludeDecoders", "Excluded decoder CSV, or empty.", true)}},
		{name: "get_capture_evidence", path: "/api/investigation/capture", session: true, description: "Read capture run/source identity, effective configuration, packet-retention coverage and producer health. Missing evidence is an error. Oversized manifests return a complete JSON artifact; select fields for bounded structured inspection.", options: []mcplib.ToolOption{apiString("fields", "Comma-separated top-level fields or JSON Pointer paths, e.g. runId,inputSHA256 or /interfaces/0.", false)}},
		{name: "get_investigation_health", path: "/api/investigation/health", session: true, description: "Read FTP data-channel or TCP reassembly health, including partial/lost evidence qualifications.", options: []mcplib.ToolOption{apiString("kind", "Health report.", true, "ftp", "reassembly")}},
		{name: "get_stream_evidence", path: "/api/investigation/streams", session: true, description: "List retained stream manifests (up to 1000 streams, span bodies omitted), or get one exact manifest by id and direction=manifest. Binary stream bodies are not returned by this tool.", options: []mcplib.ToolOption{apiString("id", "Optional stream-* id from this session.", false), apiString("direction", "Set manifest when supplying id.", false, "manifest")}},
		{name: "get_reproduction_metadata", path: "/api/investigation/reproduction", session: true, description: "Export metadata-only reproduction evidence, including failed captures. No source paths, raw logs or packet bodies. Optional runId binds generation.", options: []mcplib.ToolOption{apiString("runId", "Expected capture run id.", false)}},
		{name: "get_artifact_analysis", path: "/api/artifact-analysis", session: true, description: "Read artifact analysis and extraction qualification report. Unavailable/legacy evidence is an explicit error."},
		{name: "get_network_detection", path: "/api/network-detection", session: true, description: "Read capture-time network detector statistics, limits and dropped/unsupported evidence; inspect emitted detections with list_alerts."},
		behaviorSnapshotTool(),
		{name: "get_behavior_health", path: "/api/behavior/health", session: true, description: "Read behavioral detection coverage and health qualifications."},
		{name: "get_asset_context", path: "/api/behavior/asset", session: true, description: "Read qualified asset context, learned facts and inventory for one observed asset.", options: []mcplib.ToolOption{apiString("asset", "Asset identifier from get_behavior.", true)}},
		{name: "get_behavior_records", path: "/api/behavior/records", session: true, description: "Read bounded Connection/SMB candidates for one behavioral alert. Preserve tuple/time-only qualification and truncation; these are not exact occurrence bindings.", options: []mcplib.ToolOption{apiString("alertId", "Alert identifier from list_alerts.", true)}},
		{name: "get_behavior_topology", path: "/api/behavior/topology", session: true, description: "Read bounded behavioral topology as JSON.", options: []mcplib.ToolOption{apiInteger("maxNodes", "Maximum nodes.", 1, 500, false), apiString("scope", "Optional topology scope.", false)}},
		{name: "change_behavior", path: "/api/behavior/change", post: true, session: true, destructive: true, description: "Change behavioral baseline state or inventory using the exact version from get_behavior (optimistic concurrency). Actions are approve, pause, resume, relearn, reset, acknowledge, approve-changes, suppress, unsuppress, inventory. IDs select facts; inventory edits use inventory.id. Backend validates reasons, readiness and stale versions.", options: []mcplib.ToolOption{mcplib.WithInputSchema[behaviorChangeRequest]()}},
		{name: "list_offline_rule_packs", path: "/api/rules/offline/packs", description: "Discover netcap-offline-rules/v1 YAML example and finite execution limits. Validate then execute a pack on a completed session."},
		{name: "validate_offline_rule_pack", path: "/api/rules/offline/validate", post: true, readOnlyPost: true, description: "Parse and validate inline netcap-offline-rules/v1 YAML without executing it or changing captures.", options: []mcplib.ToolOption{apiString("yaml", "Complete offline rule pack YAML.", true)}},
		{name: "execute_offline_rule_pack", path: "/api/rules/offline/execute", post: true, session: true, bodySession: true, description: "Execute a validated inline offline rule pack on one completed session with backend finite scan limits. Persists an evaluation and alerts; inspect list_offline_evaluations and list_alerts. Does not replace capture results.", options: []mcplib.ToolOption{apiString("yaml", "Complete offline rule pack YAML.", true)}},
		{name: "list_offline_evaluations", path: "/api/rules/offline/evaluations", session: true, description: "Read persisted offline rule evaluations, including errors and coverage limits for one completed session."},
		{name: "get_protobuf_status", path: "/api/proto/status", description: "Read loaded custom Protobuf schemas, compile errors and port mappings."},
		{name: "list_protobuf_messages", path: "/api/proto/messages", description: "Discover message types in the loaded custom Protobuf schema registry."},
		{name: "add_protobuf_search_path", path: "/api/proto/search-paths", post: true, description: "Add an absolute dedicated schema directory or regular .proto file and recompile. System roots/symlinks are rejected; sources are snapshotted within 256 files (2 MiB each), 16 MiB total, 10000 entries and 16 levels. This changes the process-wide registry; inspect get_protobuf_status for compile errors.", options: []mcplib.ToolOption{apiString("path", "Absolute dedicated schema directory or regular .proto file.", true)}},
		{name: "recompile_protobuf_schemas", path: "/api/proto/recompile", post: true, description: "Recompile the configured custom Protobuf schema search paths; inspect returned status/errors before child reanalysis."},
		{name: "set_protobuf_mapping", path: "/api/proto/mappings", post: true, description: "Map a port to a loaded custom Protobuf message type. Paths/mappings/preferences reach subsequent analyses and retained child reanalysis, including helper processes. Existing results remain unchanged; inspect get_protobuf_status for compile status.", options: []mcplib.ToolOption{apiInteger("port", "TCP/UDP port.", 1, 65535, true), apiString("messageType", "Fully qualified loaded message type.", true)}},
	}
	for _, tool := range tools {
		if err := s.registerAPITool(tool); err != nil {
			return err
		}
	}
	return s.registerQualifiedQueryTools()
}

type behaviorChangeRequest struct {
	SessionID string                 `json:"session_id"`
	Action    string                 `json:"action" jsonschema:"enum=approve,enum=pause,enum=resume,enum=relearn,enum=reset,enum=acknowledge,enum=approve-changes,enum=suppress,enum=unsuppress,enum=inventory"`
	Version   uint64                 `json:"version"`
	Reason    string                 `json:"reason"`
	IDs       []string               `json:"ids,omitempty"`
	Inventory *behaviorInventoryEdit `json:"inventory,omitempty"`
}

type behaviorInventoryEdit struct {
	ID     string `json:"id"`
	Name   string `json:"name,omitempty"`
	Role   string `json:"role,omitempty"`
	Notes  string `json:"notes,omitempty"`
	Prefix string `json:"prefix,omitempty"`
}

func (s *Server) registerQualifiedQueryTools() error {
	timeRange := []mcplib.ToolOption{apiString("startNs", "Inclusive start: exact decimal capture nanoseconds.", true), apiString("endNs", "Inclusive end: exact decimal capture nanoseconds.", true)}
	timeline := []mcplib.ToolOption{apiString("start", "Exact decimal start nanoseconds.", false), apiString("end", "Exact decimal end nanoseconds.", false), apiString("types", "CSV of timeline tracks from get_timeline_meta.", false), apiString("host", "Host filter.", false), apiString("q", "Search text.", false), apiString("communityId", "Community ID filter.", false), apiString("generation", "Generation returned by get_timeline_meta; required with cursors.", false)}
	flow := append(append([]mcplib.ToolOption{}, timeRange...), apiString("filter", "Connection filter expression.", false), apiString("groupBy", "Aggregation key.", false, "srcIP", "dstIP", "dstPort", "protocol", "pair", "hostPair"), apiString("sortBy", "Ranking metric.", false, "bytes", "packets", "records", "peers", "ports", "duration", "rate"), apiInteger("limit", "Maximum groups (backend default 100).", 1, 500, false), apiInteger("offset", "Page offset.", 0, 10000, false), apiString("expectedSHA256", "Expected Connection audit-file SHA256, binds pages to unchanged evidence.", false), apiString("windowMode", "Whole-observation time selection; counters are not clipped.", false, "overlap", "contained", "start", "end"), apiString("bucketNs", "Optional exact decimal bucket width in nanoseconds.", false))
	exports := append(append([]mcplib.ToolOption{}, timeRange...), apiString("exporter", "Exporter IP:port (IPv6 bracketed).", true), apiString("format", "Export protocol.", true, "netflow-v5", "netflow-v9", "ipfix", "sflow-v5"), apiInteger("domain", "Observation domain/source id, including zero.", 0, 4294967295, true), apiString("timeBasis", "Timestamp basis.", false, "flow", "receive"), apiString("host", "Optional IP or CIDR.", false), apiString("groupBy", "Aggregation key.", false, "srcIP", "dstIP", "dstPort", "protocol", "ingress", "egress", "ingressEgress", "srcAS", "dstAS", "nextHop", "srcPrefix", "dstPrefix"), apiInteger("limit", "Maximum groups (default 100).", 1, 500, false), apiString("ingress", "Exact decimal ingress interface id.", false), apiString("egress", "Exact decimal egress interface id.", false), apiString("nextHop", "Next-hop IP filter.", false))
	for _, tool := range []apiTool{
		{name: "get_timeline_meta", path: "/api/timeline/meta", session: true, description: "Discover timeline tracks, capture time bounds and generation for stable event pagination."},
		{name: "query_timeline_events", path: "/api/timeline/events", session: true, description: "Read a bounded timeline event page. Preserve exact timestamp strings and occurrence references; pass generation plus returned after/before cursor to continue.", options: append(append([]mcplib.ToolOption{}, timeline...), apiInteger("limit", "Maximum events.", 1, 500, false), apiString("after", "Forward cursor (exclusive with before).", false), apiString("before", "Backward cursor (exclusive with after).", false))},
		{name: "get_timeline_buckets", path: "/api/timeline/buckets", session: true, description: "Read bounded per-track timeline density buckets with generation and coverage qualifications.", options: append(append([]mcplib.ToolOption{}, timeline...), apiInteger("buckets", "Number of density buckets.", 1, 500, false))},
		{name: "query_flows", path: "/api/flows/query", session: true, description: "Reconcile cumulative Connection snapshots before aggregation and ranking; returns source hash, observation references, statistics and coverage limitations. Whole counters overlap time windows; they are not clipped.", options: flow},
		{name: "query_flow_exports", path: "/api/flows/exports/query", session: true, description: "Query one exporter/format/domain scope of normalized NetFlow/IPFIX/sFlow observations. Preserves exporter-reported counters, sampling and collection-health limitations; excludes unquantifiable/cumulative counters from additive rankings.", options: exports},
		{name: "get_related_evidence", path: "/api/evidence/related", session: true, description: "Find qualified related records through an evidence id, type+ordinal, or observation identity. Links retain certainty, missing coverage and limitations; use resolve_audit_occurrence for content-bound exact resolution.", options: []mcplib.ToolOption{apiString("id", "Evidence id.", false), apiString("type", "Audit type.", false), apiInteger("ordinal", "Zero-based audit ordinal.", 0, 1000000000, false), apiString("observationId", "Connection observation id.", false), apiString("communityId", "Community ID.", false), apiString("time", "Exact decimal timestamp nanoseconds.", false)}},
	} {
		if err := s.registerAPITool(tool); err != nil {
			return err
		}
	}
	return nil
}
