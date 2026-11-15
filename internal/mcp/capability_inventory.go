package mcp

import (
	"context"
	"fmt"
	"strings"

	mcplib "github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

type capability struct {
	ID       string   `json:"id"`
	Tools    []string `json:"tools"`
	Contract string   `json:"contract"`
}

func capabilities() []capability {
	group := func(id, tools, contract string) capability { return capability{id, strings.Fields(tools), contract} }
	return []capability{
		group("discovery", "get_capability_inventory get_operator_bindings get_features set_feature list_decoders list_network_interfaces", "Explicit workflow inventory, optional operator-enrollment discovery and runtime feature/interface discovery; tool allow/deny lists still apply."),
		group("sessions", "ingest_pcap list_sessions get_session_info list_audit_records reanalyze_session wait_for_session delete_session", "PCAP admission, bounded retained child reanalysis and session lifecycle."),
		group("configuration", "get_analysis_config get_analysis_settings set_analysis_settings get_bpf_config set_bpf_config get_decoder_config set_decoder_config", "Explicit capture selection for reads; future analyses and child helpers receive current runtime settings."),
		group("records", "query_audit_records get_audit_record_fields get_audit_record_values", "All registered record schemas, including new protocols; no dedicated wrapper needed per audit type."),
		group("inventory", "list_hosts list_devices list_services list_connections get_protocol_hierarchy get_conversation list_domains list_http_records list_certificates list_fingerprints list_secrets list_auth_activity list_software list_vulnerabilities get_chart_data", "Explicit dataset queries preserve producer identity/qualification fields."),
		group("enrichment", "lookup_cve resolve lookup_dhcp_fingerprint", "Local enrichment and optional NVD lookup; DHCP catalogue remains disabled pending independently sourced data."),
		group("analyst", "get_analyst_capabilities get_analyst_binding query_capture_catalogue resolve_audit_occurrence list_bound_occurrences analyst_workspace review_diagnostic_log inspect_bound_capture", "Versioned content-bound source/occurrence workflows, saved workspace and reviewed diagnostics."),
		group("evidence", "get_capture_evidence get_investigation_health get_stream_evidence get_stream_content get_reproduction_metadata get_artifact_analysis get_related_evidence export_packet_evidence carve_subpcap_for_host carve_subpcap_for_connection carve_subpcap_for_http_pair carve_subpcap_for_certificate read_mcp_artifact", "Verified directional pages, original bytes and capture provenance; connection format=evidence produces PCAPNG/provenance ZIP."),
		group("files", "list_extracted_files get_extracted_file_content extract_iocs_from_file get_image_exif", "Session-confined extracted body/file bytes, IOC and EXIF analysis."),
		group("flows", "query_flows query_flow_exports flow_receiver get_timeline_meta query_timeline_events get_timeline_buckets", "Cumulative-counter reconciliation, owned bounded UDP receiver lifecycle, scoped exporter metadata and generation-bound timeline pagination."),
		group("detections", "get_network_detection get_behavior_health list_yara_rules get_yara_status execute_yara_scan list_alerts list_alerts_grouped get_alert_stats list_rules execute_detection_rules list_offline_rule_packs validate_offline_rule_pack execute_offline_rule_pack list_offline_evaluations", "Capture-time coverage plus YARA and bounded offline rule execution/evaluation history."),
		group("behavior", "get_behavior get_asset_context get_behavior_records get_behavior_topology change_behavior", "Paged baseline facts/inventory with coverage counters and explicit version-checked decisions."),
		group("protobuf", "get_protobuf_status list_protobuf_messages add_protobuf_search_path recompile_protobuf_schemas set_protobuf_mapping configure_protobuf", "Runtime paths/mappings reach subsequent helper analyses and child reanalysis."),
		group("live_capture", "start_live_capture get_live_capture_status stop_live_capture delete_live_capture", "Owned local-host capture, explicit interface/duration/retention, optional NC_LIVE_INTERFACES restriction, graceful stop and completed-output cleanup. Service-mode tenant capture is excluded."),
		group("protocol_experiments", "interpret_protocol_grammar interpret_stream_grammar analyze_tls_capture generate_protocol_cases generate_protocol_corpus run_protocol_exchange run_protocol_campaign run_protocol_access_matrix run_protocol_boundary reproduce_protocol_case import_protocol_triage start_protocol_listener get_protocol_job stop_protocol_job", "Core protocoltest framing/TLV/grammar, generation, state/role/boundary controls, reset-aware minimization and managed one-session listeners/proxies. Existing network policy applies to active operations."),
		group("distributed_configuration", "prepare_distributed_configuration", "Actual TLS identity/pin and enrollment validation plus exact CLI argv. Does not provision or supervise a daemon; cmd/agent/main.go NewClient starts a long-lived sender, cmd/collect/main.go owns a TLS listener and persistent sink."),
		group("firewall", "evaluate_firewall_policy", "Offline policy compilation/simulation. Live single-target deployment already uses netcap-policycontrol at /mcp (get_policy_capabilities, check_policy_bundle, stage_policy_revision, activate_policy_deployment, rollback_policy_deployment, query_policy_audit). Fleet uses netcap-firewall-fleet /mcp (fleet_capabilities, fleet_stage, fleet_rollout, fleet_activate, fleet_drain, fleet_status). Connect using that service's scoped credential; capture credentials are not forwarded."),
		group("sensor_bundles", "sensor_bundle", "Optional startup-enrolled sensor authority: seal, bounded signed artifact export/import, inbox import, discovery and native scoped expiry pruning. Fixed identity/key/namespace/retention; no per-call trust substitution. get_operator_bindings reports unconfigured state."),
		group("durable_alert_delivery", "alert_delivery", "Optional startup-enrolled endpoint/credential/outbox binding: enqueue actual capture alerts, inspect durable status and deliver/retry by stable delivery_id. Native destination pinning, at-least-once receipts and network policy remain enforced; no caller-selected destination or token."),
	}
}

func (s *Server) registerCapabilityInventory() error {
	return s.addTool(server.ServerTool{Tool: mcplib.NewTool("get_capability_inventory", mcplib.WithDescription("Discover every capture MCP workflow, exact tool coverage, native scoped firewall MCP entrypoints and explicit configuration-only boundaries. Does not contact other servers or share credentials."), mcplib.WithReadOnlyHintAnnotation(true)), Handler: func(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
		if len(req.GetArguments()) != 0 {
			return errResult(fmt.Errorf("capability inventory takes no arguments")), nil
		}
		inventory := capabilities()
		available := s.mcpSrv.ListTools()
		for i := range inventory {
			filtered := []string{}
			for _, name := range inventory[i].Tools {
				if available[name] != nil {
					filtered = append(filtered, name)
				}
			}
			inventory[i].Tools = filtered
		}
		return jsonResult(map[string]any{"version": 1, "capabilities": inventory, "network_enabled": s.networkAllowed, "response_limit_bytes": MaxResponseBytes}), nil
	}})
}
