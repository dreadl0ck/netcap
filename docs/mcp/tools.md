# MCP tool reference

Every entry below is one tool name you can call on the netcap MCP server (`net mcp`). For setup and a worked workflow, see [AI agents and MCP](../mcp.md).

## Sessions

A `session_id` is either a 32-character hex ID (service mode) or an absolute filesystem path (local mode). Pass back exactly what `ingest_pcap` or `list_sessions` returned.

## Response limits

* Every tool response is capped at 256 KiB. If a response is too large, the tool returns an error that tells the agent to paginate.
* `query_audit_records` and the `list_*` tools take `limit` and `offset`.
* Ingest and reanalysis return immediately. Poll `get_session_info` and wait for `completed`, or call `wait_for_session`. YARA scans and detection-rule runs block until they finish.

## Hints

Each tool carries the standard MCP hint annotations: read-only, destructive, idempotent and open-world. Your client should ask the user before it calls a destructive tool.

## Bound captures

The analyst tools work on a bound capture, identified by an object with these fields.

**`source`**

| name        | type   | required | description                                                             |
| ----------- | ------ | -------- | ----------------------------------------------------------------------- |
| `binding`   | object | yes      | `runId`, `sourceSHA256` and `manifestSHA256`, all strings, all required |
| `sessionId` | string |          | Session identifier                                                      |
| `inputFile` | string |          | Path of the input file                                                  |

**`reference`** points to one exact audit record occurrence. All fields are required.

| name           | type    | description                               |
| -------------- | ------- | ----------------------------------------- |
| `version`      | integer | Reference format version                  |
| `binding`      | object  | `runId`, `sourceSHA256`, `manifestSHA256` |
| `type`         | string  | Audit record type                         |
| `file`         | string  | Audit file                                |
| `fileSHA256`   | string  | Hash of the audit file                    |
| `ordinal`      | string  | Record position in the file               |
| `recordSHA256` | string  | Hash of the record                        |
| `timestampNs`  | string  | Capture time in Unix nanoseconds          |

## Tool catalogue (56 tools)

### `analyst_workspace`

Load saved queries and reports from the local workspace when `document` is absent. Saving a document requires `expectedRevision` (compare-and-swap), and new documents must be drafts. A review needs unchanged persisted content and a named reviewer. Nothing is approved automatically.

**Arguments:**

| name               | type           | required | description                    |
| ------------------ | -------------- | -------- | ------------------------------ |
| `source`           | source         | yes      | Bound capture                  |
| `expectedRevision` | integer        | yes      | Revision you expect to replace |
| `document`         | object or null |          | Document to save; omit to load |

**`document` fields:**

| name                      | type               | required | description                                                                 |
| ------------------------- | ------------------ | -------- | --------------------------------------------------------------------------- |
| `includedSources`         | array of source    | yes      | Sources the document covers                                                 |
| `id`                      | string             | yes      |                                                                             |
| `revision`                | integer            | yes      |                                                                             |
| `kind`                    | string             | yes      |                                                                             |
| `title`                   | string             | yes      |                                                                             |
| `body`                    | string             | yes      |                                                                             |
| `binding`                 | object             | yes      | `runId`, `sourceSHA256`, `manifestSHA256`                                   |
| `references`              | array of reference | yes      |                                                                             |
| `review`                  | string             | yes      |                                                                             |
| `updatedAt`               | string             | yes      |                                                                             |
| `catalogueSnapshotSHA256` | string             |          |                                                                             |
| `query`                   | object or null     |          | `kind` (string), `value` (string), `types` (array of strings), all required |
| `reviewer`                | string             |          |                                                                             |

### `carve_subpcap_for_certificate`

Write a sub-PCAP for the TCP flow that carried a given TLS certificate, identified by its 4-tuple.

**Hints:** read-only, idempotent

**Arguments:**

| name         | type   | required | description                                                              |
| ------------ | ------ | -------- | ------------------------------------------------------------------------ |
| `dst_ip`     | string | yes      | Destination IP                                                           |
| `dst_port`   | string | yes      | Destination port                                                         |
| `end_ns`     | string |          | Inclusive end time in UTC Unix nanoseconds; use together with `start_ns` |
| `run_id`     | string |          | Expected capture generation; the backend rejects stale generations       |
| `session_id` | string | yes      | Session identifier                                                       |
| `src_ip`     | string | yes      | Source IP of the TLS flow                                                |
| `src_port`   | string | yes      | Source port                                                              |
| `start_ns`   | string |          | Inclusive start time in UTC Unix nanoseconds; use together with `end_ns` |

### `carve_subpcap_for_connection`

Write a bidirectional sub-PCAP for a TCP or UDP tuple. Optional inclusive time bounds narrow the result when the tuple was reused. Without bounds, all matching occurrences are included.

**Hints:** read-only, idempotent

**Arguments:**

| name         | type   | required | description                                                              |
| ------------ | ------ | -------- | ------------------------------------------------------------------------ |
| `dst_ip`     | string | yes      | Destination IP                                                           |
| `dst_port`   | string | yes      | Destination port                                                         |
| `end_ns`     | string |          | Inclusive end time in UTC Unix nanoseconds; use together with `start_ns` |
| `protocol`   | string | yes      | Transport protocol                                                       |
| `run_id`     | string |          | Expected capture generation; the backend rejects stale generations       |
| `session_id` | string | yes      | Session identifier                                                       |
| `src_ip`     | string | yes      | Source IP                                                                |
| `src_port`   | string | yes      | Source port                                                              |
| `start_ns`   | string |          | Inclusive start time in UTC Unix nanoseconds; use together with `end_ns` |

### `carve_subpcap_for_host`

Write a sub-PCAP with all traffic involving one host IP. Returns the file's path on disk, its sha256 and a `netcap://carve/{id}` resource URI for direct byte access.

**Hints:** read-only, idempotent

**Arguments:**

| name         | type   | required | description                                                        |
| ------------ | ------ | -------- | ------------------------------------------------------------------ |
| `host`       | string | yes      | Host IP (v4 or v6)                                                 |
| `run_id`     | string |          | Expected capture generation; the backend rejects stale generations |
| `session_id` | string | yes      | Session identifier                                                 |

### `carve_subpcap_for_http_pair`

Write a bidirectional sub-PCAP for an observed HTTP TCP tuple, including nonstandard ports. Without time bounds, all matching occurrences of the tuple are included.

**Hints:** read-only, idempotent

**Arguments:**

| name         | type   | required | description                                                              |
| ------------ | ------ | -------- | ------------------------------------------------------------------------ |
| `dst_ip`     | string | yes      | Destination IP                                                           |
| `dst_port`   | string | yes      | Observed destination port                                                |
| `end_ns`     | string |          | Inclusive end time in UTC Unix nanoseconds; use together with `start_ns` |
| `run_id`     | string |          | Expected capture generation; the backend rejects stale generations       |
| `session_id` | string | yes      | Session identifier                                                       |
| `src_ip`     | string | yes      | Source IP                                                                |
| `src_port`   | string | yes      | Observed source port                                                     |
| `start_ns`   | string |          | Inclusive start time in UTC Unix nanoseconds; use together with `end_ns` |

### `delete_session`

Remove a session from the netcap WebUI and delete its files on disk (uploads, results and error logs). Service mode only. In local mode the CLI process owns the sessions and cleans them up on exit.

**Hints:** destructive, idempotent

**Arguments:**

| name         | type   | required | description                              |
| ------------ | ------ | -------- | ---------------------------------------- |
| `session_id` | string | yes      | Session identifier (service-mode hex ID) |

### `execute_detection_rules`

Run all enabled netcap detection rules against the session. Blocks until done. The response has per-rule results, and new alerts also appear in `list_alerts`.

**Hints:** idempotent

**Arguments:**

| name         | type   | required | description        |
| ------------ | ------ | -------- | ------------------ |
| `session_id` | string | yes      | Session identifier |

### `execute_yara_scan`

Run all loaded YARA rules against the session's extracted files. Blocks until the scan finishes, which takes seconds to a few minutes (the HTTP client times out after 5 minutes). The response contains all matches.

**Hints:** idempotent

**Arguments:**

| name         | type   | required | description        |
| ------------ | ------ | -------- | ------------------ |
| `session_id` | string | yes      | Session identifier |

### `extract_iocs_from_file`

Scan one carved file for indicators of compromise: URLs, hostnames, domains, IPv4 and IPv6 addresses and email addresses. Returns all kinds by default. Restrict them with `kinds`. The file is read the same way as in `get_extracted_file_content`.

**Hints:** read-only, idempotent

**Arguments:**

| name           | type   | required | description                                                          |
| -------------- | ------ | -------- | -------------------------------------------------------------------- |
| `file_path`    | string | yes      | Relative path inside `files/`, as returned by `list_extracted_files` |
| `kinds`        | string |          | Comma-separated kinds: `url`, `domain`, `ip`, `email`. Default: all  |
| `max_per_kind` | number |          | Maximum distinct matches per kind (default 200, max 5000)            |
| `session_id`   | string | yes      | Session identifier                                                   |

### `get_alert_stats`

Summary statistics for the alerts in this session.

**Hints:** read-only, idempotent

**Arguments:**

| name         | type   | required | description        |
| ------------ | ------ | -------- | ------------------ |
| `session_id` | string | yes      | Session identifier |

### `get_analyst_binding`

Get the registered capture binding for analyst version 1 workflows. `diagnostic=true` also allows failed captures, for log review.

**Hints:** read-only, destructive, open-world

**Arguments:**

| name         | type    | required | description |
| ------------ | ------- | -------- | ----------- |
| `diagnostic` | boolean |          |             |
| `inputFile`  | string  |          |             |
| `sessionId`  | string  |          |             |

### `get_analyst_capabilities`

Read the analyst contract versions, limits, source policy and supported catalogue field paths. Does not select or scan a capture.

**Hints:** read-only, destructive

**Arguments:** none

### `get_audit_record_fields`

Return the field schema of one audit record type: name, Go-style type (string, int, bool, repeated, struct) and whether the field is nested. Use these field names in `query_audit_records` filters.

**Hints:** read-only, idempotent

**Arguments:**

| name   | type   | required | description                                                 |
| ------ | ------ | -------- | ----------------------------------------------------------- |
| `type` | string | yes      | Audit record type name without the `NC_` prefix, e.g. `DNS` |

### `get_audit_record_values`

For one audit record type in a session, return the distinct values observed for each field. This is a quick cardinality overview to read before you write a filter.

**Hints:** read-only, idempotent

**Arguments:**

| name         | type   | required | description                                     |
| ------------ | ------ | -------- | ----------------------------------------------- |
| `session_id` | string | yes      | Session identifier                              |
| `type`       | string | yes      | Audit record type name without the `NC_` prefix |

### `get_chart_data`

Aggregate one audit record field as a time series. Use it to find beaconing (connections at regular intervals), DGA activity, or any other per-field trend over time. Returns JSON: `{type, field, interval, data: [{timestamp, value}], count, min_value, max_value, avg_value}`.

Use `get_audit_record_fields` to find the available fields.

**Hints:** read-only, idempotent

**Arguments:**

| name              | type   | required | description                                                                                         |
| ----------------- | ------ | -------- | --------------------------------------------------------------------------------------------------- |
| `field`           | string | yes      | Numeric or boolean field to aggregate. Use dot notation for nested fields, e.g. `Questions[0].Name` |
| `interval`        | string |          | Bucket size as a Go duration (`1s`, `100ms`, `1m`, `1h`). Default `1s`                              |
| `max_data_points` | number |          | Down-sample to this many points. Default 1000, max 10000                                            |
| `session_id`      | string | yes      | Session identifier                                                                                  |
| `type`            | string | yes      | Audit record type name without the `NC_` prefix, e.g. `Connection`                                  |

### `get_conversation`

Return the detailed conversation (bidirectional flow) for a 4-tuple.

**Hints:** read-only, idempotent

**Arguments:**

| name         | type   | required | description        |
| ------------ | ------ | -------- | ------------------ |
| `dst_ip`     | string | yes      | Destination IP     |
| `dst_port`   | string | yes      | Destination port   |
| `session_id` | string | yes      | Session identifier |
| `src_ip`     | string | yes      | Source IP          |
| `src_port`   | string | yes      | Source port        |

### `get_extracted_file_content`

Return a chunk of one extracted file as hex. Use `offset` and `limit` to page through the file (at most 64 KiB per call). Use it to inspect a suspicious payload before you run YARA or a disassembler.

**Hints:** read-only, idempotent

**Arguments:**

| name         | type   | required | description                                                                                  |
| ------------ | ------ | -------- | -------------------------------------------------------------------------------------------- |
| `file_path`  | string | yes      | Relative path inside the session's `files/` directory, as returned by `list_extracted_files` |
| `limit`      | number |          | Bytes to read (default 16384, max 65536)                                                     |
| `offset`     | number |          | Byte offset to start at (default 0)                                                          |
| `session_id` | string | yes      | Session identifier                                                                           |

### `get_image_exif`

Parse the EXIF metadata of a carved image. Returns a flat list of `{ifd_path, tag_id, tag_name, type_name, value}` entries, or an empty list if the image has no EXIF segment.

**Hints:** read-only, idempotent

**Arguments:**

| name         | type   | required | description                                                          |
| ------------ | ------ | -------- | -------------------------------------------------------------------- |
| `file_path`  | string | yes      | Relative path inside `files/`, as returned by `list_extracted_files` |
| `session_id` | string | yes      | Session identifier                                                   |

### `get_live_capture_status`

Report whether the netcap WebUI is in live-capture mode (reading from a network interface instead of a PCAP file). Returns `{is_live_mode, is_processing, current_session, ...}` from the `/api/status` endpoint.

**Hints:** read-only, idempotent

**Arguments:** none

### `get_protocol_hierarchy`

Wireshark-style nested protocol hierarchy as JSON, with packet counts and bytes per layer.

**Hints:** read-only, idempotent

**Arguments:**

| name         | type   | required | description        |
| ------------ | ------ | -------- | ------------------ |
| `session_id` | string | yes      | Session identifier |

### `get_session_info`

Return metadata for one analysis session: completion status, error message if any, input filename and size, audit record counts per type, and `capture_provenance` (`runId`, `inputSHA256`) when available. If provenance is missing, the response has an error field saying so. Poll this tool to follow an ingest or a child analysis.

**Hints:** read-only, idempotent

**Arguments:**

| name         | type   | required | description                                                     |
| ------------ | ------ | -------- | --------------------------------------------------------------- |
| `session_id` | string | yes      | Session identifier returned by `ingest_pcap` or `list_sessions` |

### `get_yara_status`

Return the YARA engine status: enabled, rule count and last reload.

**Hints:** read-only, idempotent

**Arguments:**

| name         | type   | required | description        |
| ------------ | ------ | -------- | ------------------ |
| `session_id` | string | yes      | Session identifier |

### `ingest_pcap`

Ingest a local PCAP or PCAPNG file into a new analysis session. Returns a `session_id` immediately and ingests in the background. Poll `get_session_info` until `completed=true` before you run analysis tools. `dpi`, `bpf`, `include_decoders` and `exclude_decoders` are stored and applied on the next `reanalyze_session`, not on the initial ingest.

**Arguments:**

| name               | type    | required | description                                                    |
| ------------------ | ------- | -------- | -------------------------------------------------------------- |
| `bpf`              | string  |          | BPF filter to use on reanalysis, e.g. `tcp port 443`           |
| `dpi`              | boolean |          | Enable DPI on the next reanalysis. Default false               |
| `exclude_decoders` | string  |          | Comma-separated decoder names to exclude on reanalysis         |
| `include_decoders` | string  |          | Comma-separated decoder names to use exclusively on reanalysis |
| `path`             | string  | yes      | Absolute path of the `.pcap` or `.pcapng` file                 |

### `inspect_bound_capture`

Original capture metadata: interfaces, exact time bounds, wire and captured bytes, truncation and packet ordering. Verify the stored source hash against the included run.

**Hints:** read-only

**Arguments:**

| name     | type   | required | description   |
| -------- | ------ | -------- | ------------- |
| `source` | source | yes      | Bound capture |

### `list_alerts`

Alerts raised by detection rules, YARA and other sources in this session.

**Hints:** read-only, idempotent

**Arguments:**

| name         | type   | required | description                          |
| ------------ | ------ | -------- | ------------------------------------ |
| `limit`      | number |          | Maximum number of results            |
| `offset`     | number |          | Pagination offset                    |
| `search`     | string |          | Substring filter applied server-side |
| `session_id` | string | yes      | Session identifier                   |

### `list_alerts_grouped`

Alerts grouped by rule or source.

**Hints:** read-only, idempotent

**Arguments:**

| name         | type   | required | description        |
| ------------ | ------ | -------- | ------------------ |
| `session_id` | string | yes      | Session identifier |

### `list_audit_records`

List the audit record files of one session (`DNS.ncap.gz`, `HTTP.ncap.gz`, `Connection.ncap.gz`, ...) with record counts and sizes on disk.

**Hints:** read-only, idempotent

**Arguments:**

| name         | type   | required | description        |
| ------------ | ------ | -------- | ------------------ |
| `session_id` | string | yes      | Session identifier |

### `list_auth_activity`

Authentication timeline: successes and failures by service.

**Hints:** read-only, idempotent

**Arguments:**

| name         | type   | required | description        |
| ------------ | ------ | -------- | ------------------ |
| `session_id` | string | yes      | Session identifier |

### `list_bound_occurrences`

List up to 4096 exact occurrence references for one audit type in a bound capture. For larger sets, use `query_capture_catalogue`.

**Hints:** read-only

**Arguments:**

| name     | type   | required | description       |
| -------- | ------ | -------- | ----------------- |
| `source` | source | yes      | Bound capture     |
| `type`   | string | yes      | Audit record type |

### `list_certificates`

All TLS certificates seen in the session: issuer, subject, SANs and validity.

**Hints:** read-only, idempotent

**Arguments:**

| name         | type   | required | description                          |
| ------------ | ------ | -------- | ------------------------------------ |
| `limit`      | number |          | Maximum number of results            |
| `offset`     | number |          | Pagination offset                    |
| `search`     | string |          | Substring filter applied server-side |
| `session_id` | string | yes      | Session identifier                   |

### `list_connections`

List the reconstructed connections in the session, with bytes, packets and timing. Narrow the list with `search`, `limit` and `offset`. Sort by `total_size` to find the top talkers.

**Hints:** read-only, idempotent

**Arguments:**

| name         | type   | required | description                          |
| ------------ | ------ | -------- | ------------------------------------ |
| `limit`      | number |          | Maximum number of results            |
| `offset`     | number |          | Pagination offset                    |
| `search`     | string |          | Substring filter applied server-side |
| `session_id` | string | yes      | Session identifier                   |

### `list_decoders`

List all packet and stream decoders with descriptions. Use these names for `include_decoders` and `exclude_decoders` in `ingest_pcap` and `reanalyze_session`.

**Hints:** read-only, idempotent

**Arguments:** none

### `list_devices`

List all devices (MAC addresses) seen in the session, with vendor lookups.

**Hints:** read-only, idempotent

**Arguments:**

| name         | type   | required | description        |
| ------------ | ------ | -------- | ------------------ |
| `session_id` | string | yes      | Session identifier |

### `list_domains`

Domains queried in the session, with counts. Sort by count on the client for a top-N view.

**Hints:** read-only, idempotent

**Arguments:**

| name         | type   | required | description                          |
| ------------ | ------ | -------- | ------------------------------------ |
| `limit`      | number |          | Maximum number of results            |
| `offset`     | number |          | Pagination offset                    |
| `search`     | string |          | Substring filter applied server-side |
| `session_id` | string | yes      | Session identifier                   |

### `list_extracted_files`

All files carved from the session's traffic by the file decoder. Each entry has the MIME type, size, source and destination IPs, and a relative path to use as `file_path` in `get_extracted_file_content`.

**Hints:** read-only, idempotent

**Arguments:**

| name         | type   | required | description                          |
| ------------ | ------ | -------- | ------------------------------------ |
| `limit`      | number |          | Maximum number of results            |
| `offset`     | number |          | Pagination offset                    |
| `search`     | string |          | Substring filter applied server-side |
| `session_id` | string | yes      | Session identifier                   |

### `list_fingerprints`

JA4, JA4S and JA4SSH fingerprints seen in the session.

**Hints:** read-only, idempotent

**Arguments:**

| name         | type   | required | description                          |
| ------------ | ------ | -------- | ------------------------------------ |
| `limit`      | number |          | Maximum number of results            |
| `offset`     | number |          | Pagination offset                    |
| `search`     | string |          | Substring filter applied server-side |
| `session_id` | string | yes      | Session identifier                   |

### `list_hosts`

List all hosts (IP profiles) seen in the session, with packet and byte counts. Sort on the client for a top-talkers view.

**Hints:** read-only, idempotent

**Arguments:**

| name         | type   | required | description        |
| ------------ | ------ | -------- | ------------------ |
| `session_id` | string | yes      | Session identifier |

### `list_http_records`

All HTTP records in the session, with request and response details.

**Hints:** read-only, idempotent

**Arguments:**

| name         | type   | required | description                          |
| ------------ | ------ | -------- | ------------------------------------ |
| `limit`      | number |          | Maximum number of results            |
| `offset`     | number |          | Pagination offset                    |
| `search`     | string |          | Substring filter applied server-side |
| `session_id` | string | yes      | Session identifier                   |

### `list_network_interfaces`

List the network interfaces of the host netcap runs on. Not specific to a session. Useful only on a machine with network interfaces, for live capture.

**Hints:** read-only, idempotent

**Arguments:**

| name         | type   | required | description        |
| ------------ | ------ | -------- | ------------------ |
| `session_id` | string | yes      | Session identifier |

### `list_rules`

List the netcap detection rules available to run.

**Hints:** read-only, idempotent

**Arguments:**

| name         | type   | required | description        |
| ------------ | ------ | -------- | ------------------ |
| `session_id` | string | yes      | Session identifier |

### `list_secrets`

Credentials and secrets recovered from cleartext protocols.

**Hints:** read-only, idempotent

**Arguments:**

| name         | type   | required | description                          |
| ------------ | ------ | -------- | ------------------------------------ |
| `limit`      | number |          | Maximum number of results            |
| `offset`     | number |          | Pagination offset                    |
| `search`     | string |          | Substring filter applied server-side |
| `session_id` | string | yes      | Session identifier                   |

### `list_services`

List all detected services (host, port, banner, product) in the session.

**Hints:** read-only, idempotent

**Arguments:**

| name         | type   | required | description        |
| ------------ | ------ | -------- | ------------------ |
| `session_id` | string | yes      | Session identifier |

### `list_sessions`

List the analysis sessions on this server. In service mode this is the operator's session inventory. In CLI mode it is the pre-loaded session (if any) plus everything added with `ingest_pcap` in this process. Every entry has `session_id`, `mode`, `input_file`, `input_name`, `size_bytes`, `completed` and `status`, plus mode-specific fields. Page with `limit` and `offset`. Use `completed_only` to list only ready sessions.

**Hints:** read-only, idempotent

**Arguments:**

| name             | type    | required | description                                                            |
| ---------------- | ------- | -------- | ---------------------------------------------------------------------- |
| `completed_only` | boolean |          | Return only sessions whose analysis has completed                      |
| `failed_only`    | boolean |          | Return only failed sessions                                            |
| `limit`          | number  |          | Maximum sessions to return (default 100, max 500)                      |
| `offset`         | number  |          | Pagination offset                                                      |
| `search`         | string  |          | Case-insensitive substring match against `input_name` and `input_file` |

### `list_software`

Software products detected in the session (vendor, product and version), taken from banners, JA4 fingerprints, user agents and similar sources.

**Hints:** read-only, idempotent

**Arguments:**

| name         | type   | required | description                          |
| ------------ | ------ | -------- | ------------------------------------ |
| `limit`      | number |          | Maximum number of results            |
| `offset`     | number |          | Pagination offset                    |
| `search`     | string |          | Substring filter applied server-side |
| `session_id` | string | yes      | Session identifier                   |

### `list_vulnerabilities`

Vulnerabilities (CVE matches) flagged for the detected software.

**Hints:** read-only, idempotent

**Arguments:**

| name         | type   | required | description                          |
| ------------ | ------ | -------- | ------------------------------------ |
| `limit`      | number |          | Maximum number of results            |
| `offset`     | number |          | Pagination offset                    |
| `search`     | string |          | Substring filter applied server-side |
| `session_id` | string | yes      | Session identifier                   |

### `list_yara_rules`

List the YARA rules currently loaded for scanning extracted files.

**Hints:** read-only, idempotent

**Arguments:**

| name         | type   | required | description        |
| ------------ | ------ | -------- | ------------------ |
| `session_id` | string | yes      | Session identifier |

### `lookup_cve`

Fetch the NVD record for a CVE ID: description, CVSS v3 score and vector, CWE classifications and references. Returns an error when the server runs without `-allow-fetch` or when `NETCAP_MCP_DISABLE_NETWORK=1` is set. Results are cached in memory for 6 hours (found) or 5 minutes (not found).

**Hints:** read-only, idempotent, open-world

**Arguments:**

| name     | type   | required | description                           |
| -------- | ------ | -------- | ------------------------------------- |
| `cve_id` | string | yes      | CVE identifier, e.g. `CVE-2021-44228` |

### `lookup_dhcp_fingerprint`

DHCP fingerprint enrichment is disabled until an independently sourced catalogue is available, so this tool reports that it is disabled. Packet decoding is unaffected. The tool makes no network requests.

**Hints:** read-only, idempotent

**Arguments:**

| name          | type   | required | description                                               |
| ------------- | ------ | -------- | --------------------------------------------------------- |
| `fingerprint` | string | yes      | DHCP option list, comma-separated (e.g. `1,3,6,15,33,43`) |
| `vendor`      | string |          | Vendor Class Identifier                                   |

### `query_audit_records`

Query one audit record type in a session. Works for all \~124 record types, not only those with a dedicated `list_*` tool. Use `list_audit_records` to see which types the session has and `get_audit_record_fields` to see the fields of a type.

`filter` takes a netcap filter expression, an `expr`-style boolean over record fields. `limit` is capped at 500 per call. Page with `offset`.

**Hints:** read-only, idempotent

**Arguments:**

| name         | type    | required | description                                                                                                                                                    |
| ------------ | ------- | -------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `count_only` | boolean |          | Return only the scanned and matched counts, without record bodies                                                                                              |
| `filter`     | string  |          | Filter expression, e.g. `SrcPort == 443 && DstIP startsWith '10.'`. Field names are CamelCase as in the proto schema; list them with `get_audit_record_fields` |
| `limit`      | number  |          | Maximum records to return (default 100, max 500)                                                                                                               |
| `offset`     | number  |          | Pagination offset. Only applies when `filter` is empty                                                                                                         |
| `session_id` | string  | yes      | Session identifier                                                                                                                                             |
| `type`       | string  | yes      | Audit record type without the `NC_` prefix, e.g. `DNS`, `HTTP`, `Modbus`, `SMB`. Case-sensitive                                                                |

### `query_capture_catalogue`

Search 1 to 8 finalized captures that you list. Every match keeps its source, run, file and frame identity. Supported query kinds: `sha256`, domain, endpoint (IP or socket) and allowlisted text. `tcp://` and `udp://` endpoints need Connection transport evidence. The first source is the novelty target and the others are the baseline. Only the listed captures are searched. The call fails if the result overflows.

**Hints:** read-only

**Arguments:**

| name                     | type            | required | description                                                                         |
| ------------------------ | --------------- | -------- | ----------------------------------------------------------------------------------- |
| `sources`                | array of source | yes      | 1 to 8 bound captures                                                               |
| `query`                  | object          | yes      | `kind` (string), `value` (string), `types` (array of strings or null), all required |
| `page`                   | object or null  |          | `offset` and `limit`, both integers and required                                    |
| `expectedSnapshotSHA256` | string          |          | Catalogue snapshot you expect                                                       |

### `reanalyze_session`

Create a child analysis that is retained separately. The parent results stay available. The server-wide BPF, DPI and decoder settings apply, so configure them before you call this tool. To analyze a subset by BPF filter or time range, pass `run_id` and `source_sha256` from the parent's provenance. Poll `get_session_info` with the returned child ID.

**Hints:** destructive

**Arguments:**

| name               | type   | required | description                                                                               |
| ------------------ | ------ | -------- | ----------------------------------------------------------------------------------------- |
| `end_ns`           | string |          | Inclusive end capture time as a decimal nanosecond string; requires `start_ns`            |
| `max_output_bytes` | string |          | Output byte limit for the subset, as a decimal string (default 268435456, max 1073741824) |
| `max_packets`      | number |          | Packet limit for the subset, at most 1000000                                              |
| `run_id`           | string |          | Parent capture `runId`; required for subsets                                              |
| `selection_bpf`    | string |          | BPF filter for the child input, e.g. `host 192.0.2.10 and tcp port 9243`                  |
| `session_id`       | string | yes      | Session identifier                                                                        |
| `source_sha256`    | string |          | Parent `inputSHA256`; required for subsets                                                |
| `start_ns`         | string |          | Inclusive start capture time as a decimal nanosecond string; requires `end_ns`            |

### `resolve`

Run one of netcap's local resolvers on a value: reverse DNS, GeoIP, MAC vendor (OUI), IANA service by port, or the product behind a JA4 fingerprint. All lookups are local and make no outbound HTTP requests. The netcap databases (loaded by `net dbs` or at WebUI startup) must be on disk.

**Hints:** read-only, idempotent

**Arguments:**

| name       | type   | required | description                                                                                                                       |
| ---------- | ------ | -------- | --------------------------------------------------------------------------------------------------------------------------------- |
| `kind`     | string | yes      | One of `dns`, `geoip`, `mac_vendor`, `iana_service`, `ja4`, `ja4s`, `ja4h`, `ja4x`, `ja4t`, `ja4ts`, `ja4tscan`                   |
| `protocol` | string |          | For `iana_service`: `tcp` or `udp` (default `tcp`)                                                                                |
| `value`    | string | yes      | The key to look up: an IP for `dns` and `geoip`, a MAC for `mac_vendor`, a port for `iana_service`, a fingerprint hash for `ja4*` |

### `resolve_audit_occurrence`

Resolve the exact audit record that an occurrence reference points to. If the source, manifest, file or frame binding is stale, the call fails instead of rebinding the ordinal.

**Hints:** read-only

**Arguments:**

| name        | type      | required | description                              |
| ----------- | --------- | -------- | ---------------------------------------- |
| `source`    | source    | yes      | Bound capture                            |
| `reference` | reference | yes      | Occurrence from `list_bound_occurrences` |

### `review_diagnostic_log`

Preview a projection of log lines that contains only hashes and fixed diagnostic classes, never raw log text. Passing `approve` saves the exact preview unchanged. Use it to review a log before you attach it to a bug report.

**Arguments:**

| name      | type           | required | description                        |
| --------- | -------------- | -------- | ---------------------------------- |
| `source`  | source         | yes      | Bound capture                      |
| `file`    | string         | yes      | Log file                           |
| `start`   | integer        | yes      | First line                         |
| `end`     | integer        | yes      | Last line                          |
| `approve` | object or null |          | Approval of a previewed projection |

`approve` has these fields, all required:

| name               | type    | description                                                                          |
| ------------------ | ------- | ------------------------------------------------------------------------------------ |
| `version`          | integer |                                                                                      |
| `binding`          | object  | `runId`, `sourceSHA256`, `manifestSHA256`                                            |
| `file`             | string  |                                                                                      |
| `fileSHA256`       | string  |                                                                                      |
| `start`, `end`     | integer |                                                                                      |
| `lines`            | array   | Objects with `ordinal` (integer), `sha256` (string) and `classes` (array of strings) |
| `projectionSHA256` | string  |                                                                                      |
| `state`            | string  |                                                                                      |

### `stop_live_capture`

Stop a running live capture on the WebUI host. Returns immediately, and audit record processing continues until the buffers drain. Returns an error if the WebUI is not in live-capture mode.

**Hints:** destructive, idempotent

**Arguments:** none

### `wait_for_session`

Poll `get_session_info` on the server until the session completes or the timeout passes. Returns the final session info, so the agent does not spend conversation turns on polling.

**Hints:** read-only, idempotent

**Arguments:**

| name               | type   | required | description                                       |
| ------------------ | ------ | -------- | ------------------------------------------------- |
| `poll_interval_ms` | number |          | Polling interval (default 500, min 100, max 5000) |
| `session_id`       | string | yes      | Session identifier                                |
| `timeout_seconds`  | number |          | Maximum wait (default 60, max 300)                |
