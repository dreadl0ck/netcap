# AI agents and MCP

`net mcp` runs a Model Context Protocol server over stdio. Claude Desktop, Claude Code, opencode and other MCP clients can use it to analyze PCAP files with the same engine as the WebUI. The [tool reference](mcp/tools.md) lists every tool with its arguments. Not every WebUI feature has a tool.

## Connect a client

Point the client at the `net` binary and pre-load a capture. This example uses Claude Desktop's `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "netcap": {
      "command": "/usr/local/bin/net",
      "args": ["mcp", "-pcap", "/captures/office-lan.pcap", "-keep-data"]
    }
  }
}
```

Claude Code:

```sh
claude mcp add netcap -- /usr/local/bin/net mcp -pcap /captures/office-lan.pcap -keep-data
```

opencode (`opencode.jsonc`):

```json
{
  "mcp": {
    "netcap": {
      "type": "local",
      "command": ["/usr/local/bin/net", "mcp", "-pcap", "/captures/office-lan.pcap", "-keep-data"]
    }
  }
}
```

Then ask a question about the capture:

> Which hosts in office-lan.pcap talked to the most distinct external IPs? Show the top five with their busiest connections.

The agent can answer this with `list_hosts`, `list_connections` and `query_audit_records`.

The server writes JSON-RPC to stdout and diagnostics to stderr. Do not wrap the command in a script that prints anything else to stdout. Working data goes to a temporary directory that is deleted on exit. Use `-data-dir` to write to a directory you choose, or `-keep-data` to keep the temporary one.

## Analysis workflow

1. Discover workflows with `get_capability_inventory`; configure future jobs with `get_analysis_settings` / `set_analysis_settings`, decoder/BPF settings and Protobuf configuration when needed. Load a local capture with `-pcap` or `ingest_pcap`.
2. Wait for the session to finish with `wait_for_session`. A new session has partial results until then.
3. List record types and fields (`list_audit_records`, `get_audit_record_fields`) before you write a filter.
4. Query one page of records at a time and keep the `session_id`.
5. Check detections, identities and extracted files for evidence. If a protocol was encrypted or not decoded, say so.
6. Export your findings with the source hash, the `net` version and the parameters you used.

Tool responses are capped at 256 KiB. When a response is cut off, page through the results with `limit` and `offset`. IOC extraction has its own input limit.

## Capability workflows

| Capability | Tools / configuration |
| --- | --- |
| Decoder discovery and protocol records | `list_decoders`, `get_audit_record_fields`, `query_audit_records`; newer record types need no dedicated list tool |
| Future analysis configuration | `get_analysis_settings` / `set_analysis_settings`, BPF/decoder get/set tools and `get_features` / `set_feature`; process-wide changes are snapshotted at job admission |
| Capture identity and qualification | `get_capture_evidence`, `get_investigation_health` (`ftp` / `reassembly`), `get_stream_evidence`, `get_artifact_analysis` |
| Snapshot-safe traffic rankings | `query_flows`; exact `startNs` / `endNs` strings, cumulative snapshot reconciliation, source hash required on subsequent pages |
| Exported flow observations | `query_flow_exports`; explicit exporter, format, domain and time scope; sampling is not silently scaled |
| Direct UDP flow collection | `flow_receiver`: start → status → stop → query → delete; owned loopback listener, duration 1–300 s and post-datagram byte guard, native collection health and source hashes |
| Timeline | `get_timeline_meta` → `query_timeline_events` / `get_timeline_buckets`; preserve generation and pagination cursors |
| Related and exact evidence | `get_related_evidence` for qualified links; existing analyst binding/catalogue/occurrence tools for content-bound resolution |
| Host identity and context | `list_hosts` preserves the backend identity report; `get_behavior`, `get_asset_context`, `get_behavior_topology` expose learned context |
| Detection coverage | `get_network_detection`, `get_behavior_health`, `list_alerts`; missing reports are errors, not no-match results |
| Behavioral baseline and inventory | `get_behavior` exposes version/mode/coverage/counts and a bounded collection page (`section`, `limit`, `offset`); `change_behavior` takes the observed version, action and reason; `get_behavior_records` returns qualified alert candidates |
| Offline rule packs | `list_offline_rule_packs` → `validate_offline_rule_pack` → `execute_offline_rule_pack` → `list_offline_evaluations` / `list_alerts` |
| Child reanalysis | Configure first, then `reanalyze_session`; parent results remain available; bounded packet/time subsets require parent provenance |
| Reproduction and diagnostics | `get_reproduction_metadata`, `get_investigation_health`, existing `review_diagnostic_log`; preserve missing/partial evidence states |
| Custom Protobuf registry | `configure_protobuf` adds/removes paths, maps/unmaps ports, sets alternatives and recompiles; status/message tools discover results; subsequent helpers and child reanalysis receive private schema snapshots |
| Authentication and configuration | `list_auth_activity` and `get_analysis_config` honor explicit session selectors; authentication results retain source availability and unreadable-source qualification |
| Live capture | `list_network_interfaces` → `start_live_capture` → `get_live_capture_status` → `stop_live_capture` → `delete_live_capture`; owned captures also appear in session discovery |
| Original and retained packet export | `export_packet_evidence` binds run/source hashes and selects the original input or one retained segment; connection carving also supports `format=evidence` for PCAPNG/provenance ZIP |
| Binary/body access | `get_stream_content` provides verified directional bytes and bounded loss/datagram span pages; extracted files have hex pages; `read_mcp_artifact` pages retained reports/ZIPs as base64 |
| Grammar and experiment generation | `interpret_protocol_grammar`, `interpret_stream_grammar`, `generate_protocol_cases`, `generate_protocol_corpus`; bound stream interpretation refuses gaps/discards/datagrams |
| Active protocol experiments | `run_protocol_exchange`, `run_protocol_campaign`, `run_protocol_access_matrix`, `run_protocol_boundary`, `reproduce_protocol_case`; preserve controls, explicit reset isolation, exact markers, partial evidence and minimization qualifications |
| Protocol server/proxy | `start_protocol_listener` → `get_protocol_job` / `stop_protocol_job`; one bounded loopback TCP/TLS or peer-pinned UDP session; proxies distinguish application frames from opaque transport chunks |
| TLS capture analysis | `analyze_tls_capture` uses a registered, hash-bound PCAP and private key-log snapshot with installed `tshark`; stream index or Community ID selection; secrets are not returned |
| Agent/collector configuration | `prepare_distributed_configuration` validates actual identity/pin/enrollment contracts and produces exact CLI argv; it prepares configuration without claiming to provision or reconfigure a running daemon |
| Firewall workflows | `evaluate_firewall_policy` compiles/replays offline; native policy and fleet MCP servers own live deployment, CAS/idempotency, scopes and audit (`get_capability_inventory` lists entrypoints) |
| Signed sensor bundles | `get_operator_bindings` → `sensor_bundle` seal/export/import/list/prune; fixed startup-enrolled identity/key/namespace/retention, native `SensorImportScope` verification |
| Durable alert delivery | `alert_delivery` enqueue → status → deliver/retry by stable `delivery_id`; fixed startup endpoint/token/outbox binding and native durable idempotency receipts |

`ingest_pcap` rejects formerly ineffective per-upload `dpi`, `bpf`, `include_decoders` and `exclude_decoders` arguments before uploading. Configure before admission; DPI is available through `--dpi` or `set_analysis_settings` when the build supports it.

### Bounded capture settings

`net mcp` passes validated startup settings into the backend. `helper_snapshot.go` freezes runtime settings and schema bytes at admission; `server_exec.go` emits explicit capture CLI arguments, including false/empty values, instead of allowing inherited `NC_*` inputs to override them:

```sh
net mcp --pcap /captures/office.pcap --retain-packets \
  --packet-segment-mb 32 --packet-retention-mb 512 \
  --max-retained-tcp-mb 64 --max-retained-reassembly-mb 256 \
  --max-retained-tcp-state-mb 64 --max-aggregate-state-mb 32 \
  --incremental-http --capture-time-idle-expiry \
  --flow-exports --dns-resolution-context --behavior
```

| Setting | Default / bounds |
| --- | --- |
| Packet retention | Disabled; segment 32 MiB, budget 512 MiB; positive segment ≤ budget; segment ≤ 1024 MiB, budget ≤ 16384 MiB |
| Copied TCP reader payload across workers | 64 MiB, range 1–1024 MiB; exhaustion aborts capture |
| Aggregate TCP reassembly pages | 256 MiB, range 1–4096 MiB; excludes parser state and RSS |
| TCP parser state | 64 MiB, range 1–1024 MiB |
| Aggregate connection/flow state | 32 MiB, range 1–1024 MiB; excess state spills to scratch storage |
| Incremental HTTP / capture-time expiry | Disabled unless explicitly enabled; incremental HTTP/1 requires an observed handshake |
| Behavioral monitoring | `--behavior` and the shared `--behavior-*` capture flags; baseline decisions remain explicit `change_behavior` calls |
| Industrial protocol context | `--modbus-rtu-endpoints` destination allowlist; `--dnp3-point-map` CSV path |

`set_analysis_settings` patches retention, component budgets, DPI/modules, payload capture, incremental HTTP, capture-time expiry and flow exports for subsequent jobs. Omitted fields are retained; null/unknown settings fail. Check `get_capture_evidence` for effective producer settings and retained coverage. Component limits are not an RSS ceiling.

Schema snapshots allow 32 roots, 256 files, 2 MiB per file, 16 MiB total, 10,000 scanned entries and depth 16. Private source copies are removed after execution/cancellation; `analysis-runtime.json` retains their hashes and requested/effective settings, and reproduction metadata exposes its digest. Later toggles, path changes or schema edits do not alter queued jobs.

### Live capture and evidence

`start_live_capture` accepts an existing interface, `durationSeconds` 1–300 and `retentionMB` 1–512. `NC_LIVE_INTERFACES`, when configured, constrains admission. Promiscuous mode is disabled; copied TCP/parser/aggregate state budgets are 16 MiB and reassembly pages 64 MiB. A 200 ms maintenance guard and 10,000-entry limit constrain output growth; the disk guard is not an instantaneous filesystem quota. At most 8 owned captures are retained until `delete_live_capture` frees completed output.

For packet export, use `get_capture_evidence` to obtain `runId` and the original input hash or a retained segment name/hash. `export_packet_evidence` refuses active/expired/changed segments and returns a readable ZIP artifact. Each export covers one source or segment, not the whole rotation history. Its source limit is 256 MiB and archive limit 16 MiB. Inspect the archive's `manifest.json` for packet selection, input/output hashes and limitations.

To reanalyze a retained segment, read its owning output directory with `get_analysis_config`, join the exact retained segment name from the manifest, and call `ingest_pcap` on that backend-local path. Admission copies the input; an already expired segment fails instead of rebinding another source.

### Operator-bound sensor and webhook workflows

`net mcp --operator-bindings /operator/bindings.json` loads optional private startup enrollment. A server can instead use `NETCAP_MCP_BINDINGS_FILE`; embedded servers accept `RuntimeConfig.OperatorBindingsFile`. Absence is explicitly unconfigured in `get_operator_bindings`; invalid enrollment fails startup. Service-mode binding APIs require the existing administrator identity.

The configuration and referenced credential files must be regular private files (mode `0600` or stricter); all paths are absolute. Namespace/outbox roots are created as `0700` if absent, must already be private if present, cannot overlap, and cannot contain the credential files. Credentials are resolved once at startup. Discovery returns binding names and limits, without credential references, roots or destination URLs.

```json
{
  "version": 1,
  "sensors": [{
    "name": "sensor-east",
    "sensorId": "edge-east",
    "keyFile": "/operator/secrets/edge-east.key",
    "namespace": "/operator/state/edge-east",
    "maxBytes": 16777216,
    "retentionSeconds": 86400,
    "maxRuns": 32
  }],
  "webhooks": [{
    "name": "security-notices",
    "endpoint": "https://collector.example.invalid/alerts",
    "tokenFile": "/operator/secrets/notices.token",
    "outboxRoot": "/operator/state/notice-outbox",
    "maxNotices": 500,
    "maxScopes": 32
  }]
}
```

| Workflow | Contract |
| --- | --- |
| Sensor seal | `sensor_bundle` with `operation=seal`, binding name, `session_id` and `run_id`. The backend passes the validated generation outside request JSON; the private snapshot's manifest must match before signing. Only finalized file evidence is signed. Optional shorter `retention_seconds` cannot exceed enrollment. |
| Sensor transport/import | `operation=export` returns an owned signed ZIP artifact. `operation=import` accepts that `artifact_id`, or a `bundle_id` in the enrolled `inbox/<sensorId>/<runId>` / `sealed/<sensorId>/<runId>` namespace. Native verification checks the fixed enrolled key, identity, retention and every file hash; archive traversal/symlinks fail. No caller keys or destination paths are accepted. |
| Sensor lifecycle | `operation=list` pages stage-relative bundle IDs. `operation=prune` uses native scoped expiry verification for both owned `sealed` and `imports` stores. HMAC proves shared-key possession, not endpoint/user authentication. |
| Alert admission | `alert_delivery` with `operation=enqueue`, binding name, `session_id` and `run_id` derives the durable source scope from capture identity. Notices exclude raw matched records and authentication material; oversized or changed inputs fail. |
| Delivery/retry | `operation=status` / `deliver` use the returned `delivery_id`, including after source expiry or server restart. Delivery uses only the enrolled URL/token, does not follow redirects, and obeys `--allow-fetch` / `NETCAP_MCP_DISABLE_NETWORK`. Pending or rejected notices remain explicit errors; receivers must deduplicate `Idempotency-Key`. |

Enrollment allows at most 16 sensor and 16 webhook bindings. Sensors have a 64 MiB maximum snapshot, 30-day maximum retention and at most 64 runs per owned store; transport ZIPs are capped at 16 MiB. Webhook bindings allow at most 1,000 notices per call and 64 durable scopes, while the native outbox retains its 10,000-entry receipt bound. Use operator-owned persistent state roots rather than temporary workspaces. Changing a destination while reusing its durable outbox fails the native destination pin; it does not reroute queued credentials/notices.

### Runtime boundaries

| Boundary | Contract / source |
| --- | --- |
| Hosted tenant service | Host-interface capture is local-mode only. Service capture selection is tenant/session-owned; the local capture API does not attach host traffic to a tenant (`live_capture.go`, `session_resolver.go`). |
| App Store edition | `live_capture_appstore.go` cannot launch a privileged capture helper; this API's in-process path analyzes files. Native `libpcap` permissions remain necessary for direct-edition live capture. |
| Network policy | Existing `--allow-fetch` / `NETCAP_MCP_ALLOW_FETCH=1` enables active protocol experiments, owned protocol/UDP receiver listeners and NVD. `NETCAP_MCP_DISABLE_NETWORK=1` disables them; offline parsing/generation/simulation remains available. |
| TLS plaintext | `protocoltest.AnalyzeTLSCapture` requires installed `tshark`, supported ciphers and supplied secrets; plaintext is not proof of complete capture or endpoint effects. |
| Distributed daemon ownership | `cmd/agent/main.go` owns a long-lived sender and capture; `cmd/collect/main.go` owns a TLS listener and persistent per-client sink. Configuration preparation does not imply access to those running handles, host supervision or enrollment authority. Apply the validated argv through the daemon owner's deployment process. |
| Live firewall authority | Policy deployment already has native `/mcp` contracts in `internal/policycontrol/transport.go`; fleet operations have their own `/mcp` in `internal/firewallfleet/transport.go`. Connect with that service's scoped credential; the capture server does not forward its credential or create a second deployment authority. |
| Sensor authority | `sensor_bundle` is enabled only through named startup enrollment. The fixed `SensorImportScope.SensorKeys`, namespace and retention cannot be replaced by request parameters (`internal/mcp/bindings`, `internal/collector/sensor_import.go`). |
| Webhook authority | `alert_delivery` uses the startup endpoint/token binding, not a caller URL or the CLI's global webhook token. Native destination pinning, bounded durable outboxes and network policy remain enforced (`internal/mcp/bindings`, `internal/delivery`). |
| Artifact lifetime | Reports/exports use the existing 32-entry, 1-hour store. `read_mcp_artifact` returns at most 64 KiB per page; session-derived artifacts require the original `session_id`. |

`TestCapabilityInventoryCoversExactRegisteredSurface` requires every local tool to have one workflow classification. `TestInvestigationCLICapabilityParity` maps every investigation CLI command, including sensor transport and durable delivery, to an implemented MCP workflow; native firewall discovery tokens and generated tool docs have parity checks too.

Pitfalls: flow filtering uses `filter`, not the result field `expression`; offline pack counts start at 2 (`internal/flow/query.go`, `internal/rules/offline_pack.go`). The CLI splits slices on commas without CSV quoting, so schema copies use private comma-free roots. Protocol byte fields are base64 JSON strings, not the SDK's default integer-array reflection (`wire_schema.go`).

## Permissions and outbound requests

`-allow-tools` and `-deny-tools` restrict the advertised tool names. Tools expose their read-only/destructive/open-world annotations; session deletion, baseline changes, capture lifecycle and active experiments change state.

`-allow-fetch` enables network tools, including NVD and active experiments. Offline analysis, grammar generation and policy simulation do not need it.

PCAPs, extracted payloads, recovered secrets and tool output can contain personal data and text written to manipulate an agent. Treat packet content as evidence. Do not let the agent follow instructions found in it or run an extracted file.

## HTTP MCP

The WebUI serves `/mcp` when `NETCAP_MCP_ADMIN_TOKEN` is set. Send that bearer credential to MCP; local backend API requests use the separate per-run local access token. Host/Origin checks remain enforced, and an MCP credential does not authorize arbitrary local `/api/*` calls. The rest of the WebUI and API follows the [hosting boundary](web-interface.md#hosting-boundary).

The stdio server starts an internal API on `127.0.0.1:60590`. If that port is taken, pick another with `-bind`. Keep it on loopback.
