# Netcap MCP tool reference

<!--- DO NOT EDIT — regenerate with: go test ./internal/mcp/ -run TestToolDocsUpToDate -update -->

This catalogue is generated from the live tool registry in
`internal/mcp/`. Every entry corresponds to one `tools/call`
name on the netcap MCP server.

Sessions
--------

A `session_id` here may be either a 32-char hex (service-mode session
selected via `/api/try/session/<id>`) or an absolute filesystem path
(local-mode session selected via `/api/set-directory`). The shape is
hidden behind the `session_id` argument — pass back exactly what
`ingest_pcap` or `list_sessions` returns.

Response limits
---------------

- Every tool response is capped at 256 KiB. Oversized payloads come back
  as a clear error directing the LLM to paginate.
- `query_audit_records` and the list_* tools support
  `limit` / `offset` server-side.
- Long-running operations (ingest, reanalyze) return immediately and are
  polled via `get_session_info` (look at the `completed`
  field). YARA scans and detection-rule executions are synchronous.

Hints
-----

Each tool exposes the standard MCP hint annotations (read-only,
destructive, idempotent, open-world). Treat them as advisory: a
`destructive` tool should prompt the user before invocation.

## Tool catalogue (39 tools)

Auto-generated from the live tool registry. Do not edit by hand; run `go test ./internal/mcp/ -run TestToolDocsUpToDate -update` to regenerate.

### `carve_subpcap_for_certificate`

Produce a sub-PCAP for the TCP flow that carried a given TLS certificate (identified by its 4-tuple).

**Hints:** read-only, idempotent

**Arguments:**

| name | type | required | description |
| --- | --- | --- | --- |
| `dst_ip` | string | yes | Destination IP. |
| `dst_port` | string | yes | Destination port. |
| `session_id` | string | yes | Session identifier. |
| `src_ip` | string | yes | Source IP of the TLS flow. |
| `src_port` | string | yes | Source port. |


### `carve_subpcap_for_connection`

Produce a sub-PCAP for a specific 4-tuple connection.

**Hints:** read-only, idempotent

**Arguments:**

| name | type | required | description |
| --- | --- | --- | --- |
| `dst_ip` | string | yes | Destination IP. |
| `dst_port` | string | yes | Destination port. |
| `session_id` | string | yes | Session identifier. |
| `src_ip` | string | yes | Source IP. |
| `src_port` | string | yes | Source port. |


### `carve_subpcap_for_host`

Produce a sub-PCAP filtered to all traffic involving one host IP. Returns the download URL on the netcap webui.

**Hints:** read-only, idempotent

**Arguments:**

| name | type | required | description |
| --- | --- | --- | --- |
| `host` | string | yes | Host IP (v4 or v6). |
| `session_id` | string | yes | Session identifier. |


### `carve_subpcap_for_http_pair`

Produce a sub-PCAP of all HTTP-on-TCP flows between two IPs.

**Hints:** read-only, idempotent

**Arguments:**

| name | type | required | description |
| --- | --- | --- | --- |
| `dst_ip` | string | yes | Destination IP. |
| `session_id` | string | yes | Session identifier. |
| `src_ip` | string | yes | Source IP. |


### `execute_detection_rules`

Execute all enabled netcap detection rules against the session. SYNCHRONOUS: blocks until completion. The response includes per-rule execution results; new alerts also appear in list_alerts.

**Hints:** idempotent

**Arguments:**

| name | type | required | description |
| --- | --- | --- | --- |
| `session_id` | string | yes | Session identifier. |


### `execute_yara_scan`

Run all loaded YARA rules against the session's extracted files. SYNCHRONOUS: this call blocks until the scan completes (typically seconds to a few minutes; HTTP client timeout is 5 min). The response contains the full set of matches.

**Hints:** idempotent

**Arguments:**

| name | type | required | description |
| --- | --- | --- | --- |
| `session_id` | string | yes | Session identifier. |


### `get_alert_stats`

Summary statistics for alerts in this session.

**Hints:** read-only, idempotent

**Arguments:**

| name | type | required | description |
| --- | --- | --- | --- |
| `session_id` | string | yes | Session identifier. |


### `get_audit_record_fields`

Return the field schema for one audit record type: name, Go-style type (string/int/bool/repeated/struct), and whether it's nested. Use the returned field names in query_audit_records' filter expressions.

**Hints:** read-only, idempotent

**Arguments:**

| name | type | required | description |
| --- | --- | --- | --- |
| `type` | string | yes | Audit record type name without the NC_ prefix, e.g. "DNS". |


### `get_audit_record_values`

For one audit record type in a session, return the distinct observed values per field (a fast cardinality snapshot — useful before crafting a filter).

**Hints:** read-only, idempotent

**Arguments:**

| name | type | required | description |
| --- | --- | --- | --- |
| `session_id` | string | yes | Session identifier. |
| `type` | string | yes | Audit record type name without the NC_ prefix. |


### `get_conversation`

Return the detailed conversation (bidirectional flow) for a 4-tuple.

**Hints:** read-only, idempotent

**Arguments:**

| name | type | required | description |
| --- | --- | --- | --- |
| `dst_ip` | string | yes | Destination IP. |
| `dst_port` | string | yes | Destination port. |
| `session_id` | string | yes | Session identifier. |
| `src_ip` | string | yes | Source IP. |
| `src_port` | string | yes | Source port. |


### `get_extracted_file_content`

Return a chunk of one extracted file's bytes, hex-encoded. The backing endpoint paginates: offset/limit slice into the file (limit is capped at 64 KiB per call). Use this to inspect a suspicious carved payload before running YARA or a disassembler.

**Hints:** read-only, idempotent

**Arguments:**

| name | type | required | description |
| --- | --- | --- | --- |
| `file_path` | string | yes | Relative path of the file inside the session's files/ directory, as returned by list_extracted_files. |
| `limit` | number |  | Number of bytes to read (default 16384, max 65536). |
| `offset` | number |  | Byte offset to start reading from (default 0). |
| `session_id` | string | yes | Session identifier. |


### `get_protocol_hierarchy`

Wireshark-style nested protocol hierarchy as JSON: layer counts and bytes.

**Hints:** read-only, idempotent

**Arguments:**

| name | type | required | description |
| --- | --- | --- | --- |
| `session_id` | string | yes | Session identifier. |


### `get_session_info`

Return metadata for one analysis session: completion status, error message if any, input filename and size, per-record-type audit counts. Use this to poll an in-flight ingest.

**Hints:** read-only, idempotent

**Arguments:**

| name | type | required | description |
| --- | --- | --- | --- |
| `session_id` | string | yes | Session identifier returned by ingest_pcap or list_sessions. |


### `get_yara_status`

Return YARA engine status (enabled, rule count, last reload).

**Hints:** read-only, idempotent

**Arguments:**

| name | type | required | description |
| --- | --- | --- | --- |
| `session_id` | string | yes | Session identifier. |


### `ingest_pcap`

Ingest a local PCAP/PCAPNG file into a new netcap analysis session. Returns immediately with a session_id; ingest runs asynchronously. Poll get_session_info until the session reports completed=true before running analytical tools. dpi/bpf/include_decoders/exclude_decoders are recorded and may be applied on the next reanalyze_session — they are not honoured on initial ingest in v1.

**Arguments:**

| name | type | required | description |
| --- | --- | --- | --- |
| `bpf` | string |  | Optional BPF filter to remember for reanalyze (e.g. "tcp port 443"). |
| `dpi` | boolean |  | Request DPI on the next reanalyze. Default false. |
| `exclude_decoders` | string |  | CSV of decoder names to exclude on reanalyze. |
| `include_decoders` | string |  | CSV of decoder names to include exclusively on reanalyze. |
| `path` | string | yes | Absolute filesystem path of the .pcap or .pcapng file to ingest. |


### `list_alerts`

Alerts raised by detection rules, YARA, and other sources in this session.

**Hints:** read-only, idempotent

**Arguments:**

| name | type | required | description |
| --- | --- | --- | --- |
| `limit` | number |  | Maximum number of results to return. |
| `offset` | number |  | Pagination offset. |
| `search` | string |  | Substring filter applied server-side. |
| `session_id` | string | yes | Session identifier. |


### `list_alerts_grouped`

Alerts grouped by rule/source.

**Hints:** read-only, idempotent

**Arguments:**

| name | type | required | description |
| --- | --- | --- | --- |
| `session_id` | string | yes | Session identifier. |


### `list_audit_records`

List the audit-record files produced for one session (DNS.ncap.gz, HTTP.ncap.gz, Connection.ncap.gz, ...) with their record counts and on-disk sizes.

**Hints:** read-only, idempotent

**Arguments:**

| name | type | required | description |
| --- | --- | --- | --- |
| `session_id` | string | yes | Session identifier. |


### `list_auth_activity`

Authentication activity timeline (successes/failures by service).

**Hints:** read-only, idempotent

**Arguments:**

| name | type | required | description |
| --- | --- | --- | --- |
| `session_id` | string | yes | Session identifier. |


### `list_certificates`

All TLS certificates observed in the session (issuer, subject, sans, validity).

**Hints:** read-only, idempotent

**Arguments:**

| name | type | required | description |
| --- | --- | --- | --- |
| `limit` | number |  | Maximum number of results to return. |
| `offset` | number |  | Pagination offset. |
| `search` | string |  | Substring filter applied server-side. |
| `session_id` | string | yes | Session identifier. |


### `list_connections`

List all reconstructed connections in the session, with bytes/packets and timing. Use search/limit/offset to scope. The LLM can sort by total_size for top talkers.

**Hints:** read-only, idempotent

**Arguments:**

| name | type | required | description |
| --- | --- | --- | --- |
| `limit` | number |  | Maximum number of results to return. |
| `offset` | number |  | Pagination offset. |
| `search` | string |  | Substring filter applied server-side. |
| `session_id` | string | yes | Session identifier. |


### `list_decoders`

List all available packet and stream decoders, with descriptions. Use the names returned here as values for include_decoders / exclude_decoders on ingest_pcap and reanalyze_session.

**Hints:** read-only, idempotent

**Arguments:** none


### `list_devices`

List all devices (MAC addresses) seen in the session, with vendor lookups.

**Hints:** read-only, idempotent

**Arguments:**

| name | type | required | description |
| --- | --- | --- | --- |
| `session_id` | string | yes | Session identifier. |


### `list_domains`

Domains queried in the session, with counts. Sort by count client-side for a top-N view.

**Hints:** read-only, idempotent

**Arguments:**

| name | type | required | description |
| --- | --- | --- | --- |
| `limit` | number |  | Maximum number of results to return. |
| `offset` | number |  | Pagination offset. |
| `search` | string |  | Substring filter applied server-side. |
| `session_id` | string | yes | Session identifier. |


### `list_extracted_files`

All files carved out of the session's traffic by netcap's file decoder. Each entry includes MIME type, size, source/destination IPs, and a relative path usable as `file_path` for get_extracted_file_content.

**Hints:** read-only, idempotent

**Arguments:**

| name | type | required | description |
| --- | --- | --- | --- |
| `limit` | number |  | Maximum number of results to return. |
| `offset` | number |  | Pagination offset. |
| `search` | string |  | Substring filter applied server-side. |
| `session_id` | string | yes | Session identifier. |


### `list_fingerprints`

Cryptographic fingerprints (JA4/JA4S/JA4SSH) observed in the session.

**Hints:** read-only, idempotent

**Arguments:**

| name | type | required | description |
| --- | --- | --- | --- |
| `limit` | number |  | Maximum number of results to return. |
| `offset` | number |  | Pagination offset. |
| `search` | string |  | Substring filter applied server-side. |
| `session_id` | string | yes | Session identifier. |


### `list_hosts`

List all hosts (IP profiles) seen in the session, with packet and byte counts. Sort client-side to obtain a top-talkers view.

**Hints:** read-only, idempotent

**Arguments:**

| name | type | required | description |
| --- | --- | --- | --- |
| `session_id` | string | yes | Session identifier. |


### `list_http_records`

All HTTP records in the session (request + response details).

**Hints:** read-only, idempotent

**Arguments:**

| name | type | required | description |
| --- | --- | --- | --- |
| `limit` | number |  | Maximum number of results to return. |
| `offset` | number |  | Pagination offset. |
| `search` | string |  | Substring filter applied server-side. |
| `session_id` | string | yes | Session identifier. |


### `list_network_interfaces`

List the local network interfaces visible to netcap (host-level info, not session-scoped). Useful only when running on a machine with NICs (live capture).

**Hints:** read-only, idempotent

**Arguments:**

| name | type | required | description |
| --- | --- | --- | --- |
| `session_id` | string | yes | Session identifier. |


### `list_rules`

List netcap detection rules available for execution.

**Hints:** read-only, idempotent

**Arguments:**

| name | type | required | description |
| --- | --- | --- | --- |
| `session_id` | string | yes | Session identifier. |


### `list_secrets`

Credentials / secrets recovered from cleartext protocols.

**Hints:** read-only, idempotent

**Arguments:**

| name | type | required | description |
| --- | --- | --- | --- |
| `limit` | number |  | Maximum number of results to return. |
| `offset` | number |  | Pagination offset. |
| `search` | string |  | Substring filter applied server-side. |
| `session_id` | string | yes | Session identifier. |


### `list_services`

List all detected services (host+port+banner+product) in the session.

**Hints:** read-only, idempotent

**Arguments:**

| name | type | required | description |
| --- | --- | --- | --- |
| `session_id` | string | yes | Session identifier. |


### `list_sessions`

List analysis sessions visible to this server. In service mode this returns the operator's session inventory; in CLI mode it returns the pre-loaded session (if any) plus everything uploaded via ingest_pcap in this process. Response shape is identical across modes: every entry has session_id, mode, input_file, input_name, size_bytes, completed, status, plus mode-specific fields. Use limit/offset to paginate; completed_only filters to ready sessions.

**Hints:** read-only, idempotent

**Arguments:**

| name | type | required | description |
| --- | --- | --- | --- |
| `completed_only` | boolean |  | If true, return only sessions whose analysis has completed. |
| `failed_only` | boolean |  | If true, return only sessions in a failed state. |
| `limit` | number |  | Max sessions to return (default 100, max 500). |
| `offset` | number |  | Pagination offset. |
| `search` | string |  | Case-insensitive substring match against input_name and input_file. |


### `list_software`

Software products detected in the session (vendor/product/version, sourced from banners, JA4, user-agents, etc.).

**Hints:** read-only, idempotent

**Arguments:**

| name | type | required | description |
| --- | --- | --- | --- |
| `limit` | number |  | Maximum number of results to return. |
| `offset` | number |  | Pagination offset. |
| `search` | string |  | Substring filter applied server-side. |
| `session_id` | string | yes | Session identifier. |


### `list_vulnerabilities`

Vulnerabilities flagged against detected software (CVE matches).

**Hints:** read-only, idempotent

**Arguments:**

| name | type | required | description |
| --- | --- | --- | --- |
| `limit` | number |  | Maximum number of results to return. |
| `offset` | number |  | Pagination offset. |
| `search` | string |  | Substring filter applied server-side. |
| `session_id` | string | yes | Session identifier. |


### `list_yara_rules`

List YARA rules currently loaded for scanning extracted files.

**Hints:** read-only, idempotent

**Arguments:**

| name | type | required | description |
| --- | --- | --- | --- |
| `session_id` | string | yes | Session identifier. |


### `lookup_cve`

Fetch the NVD record for a CVE id: description, CVSS v3 score and vector, CWE classifications, references. Disabled (returns an error) when the server was constructed without AllowNetwork, or when NETCAP_MCP_DISABLE_NETWORK=1 in the environment. Results are cached in-process for 6h (positive) or 5min (negative).

**Hints:** read-only, idempotent, open-world

**Arguments:**

| name | type | required | description |
| --- | --- | --- | --- |
| `cve_id` | string | yes | CVE identifier, e.g. "CVE-2021-44228". |


### `query_audit_records`

Query one audit-record type from a session (works for ALL ~124 netcap record types, not just the ones with dedicated list_* tools). Use list_audit_records to discover what's available in the session, and get_audit_record_fields to enumerate the queryable fields of a type.

Supports the netcap filter-expression language in `filter` (an `expr`-style boolean over record fields). limit caps at 500 per call; paginate with offset.

**Hints:** read-only, idempotent

**Arguments:**

| name | type | required | description |
| --- | --- | --- | --- |
| `count_only` | boolean |  | If true, return only the scanned/matched counts without record bodies. |
| `filter` | string |  | Optional filter expression (e.g. "SrcPort == 443 && DstIP startsWith '10.'"). Field names are CamelCase as in the proto schema; use get_audit_record_fields to enumerate. |
| `limit` | number |  | Maximum records to return (default 100, max 500). |
| `offset` | number |  | Pagination offset (only honoured when filter is empty). |
| `session_id` | string | yes | Session identifier. |
| `type` | string | yes | Audit record type name without the NC_ prefix, e.g. "DNS", "HTTP", "Modbus", "SMB". Case-sensitive. |


### `reanalyze_session`

Re-decode an existing session's PCAP. Server-wide BPF/DPI/decoder settings apply (configure them out-of-band before calling). Returns immediately; poll get_session_info for completion.

**Hints:** destructive

**Arguments:**

| name | type | required | description |
| --- | --- | --- | --- |
| `session_id` | string | yes | Session identifier. |


