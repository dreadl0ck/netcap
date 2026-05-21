# `net mcp` — Model Context Protocol server for netcap

`net mcp` exposes netcap's full PCAP analysis pipeline as MCP tools so an
LLM (Claude Desktop, Claude Code, mcp-inspector, etc.) can drive a complete
forensic investigation conversationally. A typical session: hand the agent a
PCAP file, ask "tell me what happened here" — the agent ingests, runs the
appropriate decoders, then iterates over hosts, flows, HTTP, TLS, files,
software, and CVEs to assemble a report.

## Usage

```bash
# Run the stdio MCP server. Most clients spawn this as a child process.
net mcp

# Pre-load a PCAP so list_sessions has something to show on first connect.
net mcp --pcap /path/to/sample.pcap

# Pin the embedded webui's loopback port (default 127.0.0.1:60590).
net mcp --bind 127.0.0.1:60590

# Restrict the tool catalogue.
net mcp --allow-tools list_hosts,list_connections,list_http_records
net mcp --deny-tools  execute_yara_scan,execute_detection_rules

# Keep the temp data dir around for inspection after the session ends.
net mcp --keep-data --data-dir /tmp/netcap-mcp-debug --debug
```

The process speaks JSON-RPC on stdin/stdout. All diagnostic logs go to
stderr by default (the MCP transport reserves stdout for JSON-RPC
frames). Pass `--quiet` to suppress logs; pass `--debug` for verbose
per-tool-call audit lines like:

```
[MCP] 2026/05/21 06:41:59.160632 tool=list_hosts duration=1.284125ms status=ok content=28 bytes
[MCP] 2026/05/21 06:41:23.926452 session select failed: set-directory ...: 404 Not Found: ...
[MCP] 2026/05/21 06:41:23.926481 tool=list_hosts duration=630.916µs status=error_result content=160 bytes
```

## Claude Desktop / Claude Code configuration

Add this to `~/Library/Application Support/Claude/claude_desktop_config.json`
(macOS) or the equivalent on your platform:

```jsonc
{
  "mcpServers": {
    "netcap": {
      "command": "/usr/local/bin/net",
      "args": ["mcp"]
    }
  }
}
```

For Claude Code, add the same entry to `.mcp.json` in your project root.

## How it works

```
LLM client (stdin/stdout JSON-RPC)
        ▲
        │  MCP stdio transport
        ▼
net mcp process
  ├─ embedded webui.Server on 127.0.0.1:60590  (no auth, loopback only)
  └─ mark3labs/mcp-go stdio server
        ├─ tool handlers ─► HTTP loopback to /api/*  ◄─ analytical logic
        ├─ resources    ─► netcap://decoders/all, netcap://session/{id}/summary
        └─ prompts      ─► triage_pcap, investigate_host, hunt_malware
```

A single `webui.Server` instance backs every tool — there is no parallel
analytical code path. PCAPs are uploaded over the loopback `/api/upload`
endpoint exactly the way a browser user would. The temp data directory is
removed when the MCP client disconnects (unless `--keep-data` is set).

## Tool catalogue (36 tools)

Grouped by domain. Every analytical tool takes a `session_id` argument
(except `list_sessions`, `list_decoders`, `list_network_interfaces`,
and `lookup_cve`). Use `ingest_pcap` to obtain a session id and
`list_sessions` to enumerate existing ones.

A `session_id` in this server is either:

- a 32-char hex (service-mode sessions selected via `/api/try/session/<id>`), or
- an absolute filesystem path (CLI-mode sessions selected via
  `/api/set-directory` with the input file path).

Always pass back the exact `session_id` returned by `ingest_pcap` or
`list_sessions` — not the original path the user typed, since the upload
endpoint copies the file to its own storage directory.

- **Pipeline (6)**: `ingest_pcap`, `list_sessions`, `get_session_info`,
  `list_decoders`, `list_audit_records`, `reanalyze_session`.
- **Inventory (4)**: `list_hosts`, `list_devices`, `list_services`,
  `list_network_interfaces`.
- **Flow (3)**: `list_connections`, `get_protocol_hierarchy`,
  `get_conversation`.
- **Protocols (6)**: `list_domains`, `list_http_records`,
  `list_certificates`, `list_fingerprints`, `list_secrets`,
  `list_auth_activity`.
- **Files / forensics (2)**: `list_extracted_files`,
  `get_extracted_file_content` (hex-encoded, paginated).
- **Threat intel (3)**: `list_software`, `list_vulnerabilities`,
  `lookup_cve`.
- **Sub-PCAP carving (4)**: `carve_subpcap_for_host`, `_connection`,
  `_http_pair`, `_certificate` — each returns a download URL for the
  carved sub-PCAP, ready to hand to Wireshark, tshark, or another tool.
  In CLI mode the URL is unauthenticated on loopback; in service mode it
  requires the admin Bearer token (the carve endpoint is part of the
  public webui API).
- **Actions / detection (8)**: `execute_yara_scan` (synchronous),
  `execute_detection_rules` (synchronous), `list_yara_rules`,
  `get_yara_status`, `list_rules`, `list_alerts`, `list_alerts_grouped`,
  `get_alert_stats`.

Aggregations (top-N, distributions, percentile views) are deliberately
not exposed as tools because the underlying webui endpoints render them
as HTML chart blobs unsuitable for an LLM. Aggregate client-side over
the corresponding `list_*` tool with `limit` and `offset`.

## Prompts (workflow playbooks)

- `triage_pcap (session_id)` — whirlwind review: top talkers, software,
  CVEs, credentials, extracted files, detection-rule alerts.
- `investigate_host (session_id, ip)` — deep dive on one host: flows,
  HTTP, TLS, software, carved sub-PCAP.
- `hunt_malware (session_id)` — file enumeration, IOC extraction, YARA,
  then carve sub-PCAPs for hits.

## Resources

- `netcap://decoders/all` — full decoder catalogue (JSON).
- `netcap://session/{session_id}/summary` — per-session triage snapshot.
- `netcap://session/active` — id of the `--pcap` pre-loaded session (CLI
  mode only).

## Service mode (admin-protected `/mcp` endpoint)

`net capture --service` mounts the same MCP server at `/mcp` when the
environment variable `NETCAP_MCP_ADMIN_TOKEN` is set. Without the token
the endpoint is not registered, so an unprotected MCP endpoint can never
be served by accident.

```bash
# Operator on try.netcap.io
NETCAP_MCP_ADMIN_TOKEN=$(openssl rand -hex 32) net capture --service ...
# logs: [MCP] Admin endpoint registered at /mcp (token fingerprint: 1a2b3c4d)
```

Clients connect with `Authorization: Bearer <token>` over the streamable
HTTP transport at `/mcp`. The auth check is constant-time; failed
requests return 401 with `WWW-Authenticate: Bearer realm="netcap-mcp"`.

## Limits

- Response bodies are capped at 256 KiB per tool call. Use `limit` and
  `offset` to keep responses small; oversized responses come back as a
  clear error directing the LLM to paginate.
- `get_extracted_file_content` returns chunks of up to 64 KiB (hex-
  encoded). Page through large files with `offset`.
- `ingest_pcap` and `reanalyze_session` return immediately and queue
  analysis on the webui's worker pool; poll `get_session_info` (the
  `completed` field) for completion. Typical ingest is sub-second to
  a few seconds per MB.
- `execute_yara_scan` and `execute_detection_rules` are SYNCHRONOUS —
  they block the HTTP call until the scan finishes. The HTTP client
  timeout is 5 minutes; large sessions may need YARA chunking
  out-of-band.
- Calls into different sessions serialise behind a single session
  selector on the underlying webui. Parallel tool calls work but queue.

## Security notes

- The CLI stdio server has no auth. Anyone who can attach to the process's
  stdin can call every tool. Don't expose `net mcp` over a network socket
  without your own auth layer.
- The CLI's embedded webui is bound to `127.0.0.1` only.
- The service-mode `/mcp` endpoint uses a single admin token. There is no
  per-tool admin gating: anyone with the token has the full tool catalogue.

## Reporting issues

File at <https://github.com/dreadl0ck/netcap/issues> with the tag
`mcp`. Include the output of `net mcp --debug` redacting any PCAP
filenames you don't want to share.
