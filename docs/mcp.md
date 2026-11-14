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

1. Load a local capture with `-pcap` or the `ingest_pcap` tool.
2. Wait for the session to finish with `wait_for_session`. A new session has partial results until then.
3. List record types and fields (`list_audit_records`, `get_audit_record_fields`) before you write a filter.
4. Query one page of records at a time and keep the `session_id`.
5. Check detections, identities and extracted files for evidence. If a protocol was encrypted or not decoded, say so.
6. Export your findings with the source hash, the `net` version and the parameters you used.

Tool responses are capped at 256 KiB. When a response is cut off, page through the results with `limit` and `offset`. IOC extraction has its own input limit.

## Permissions and outbound requests

`-allow-tools` and `-deny-tools` restrict which tools the server exposes. Also set permissions in your client: `delete_session`, `reanalyze_session` and `stop_live_capture` change state.

`-allow-fetch` lets tools query public services such as NVD (`lookup_cve`). Leave it off for purely local analysis.

PCAPs, extracted payloads, recovered secrets and tool output can contain personal data and text written to manipulate an agent. Treat packet content as evidence. Do not let the agent follow instructions found in it or run an extracted file.

## HTTP MCP

The WebUI serves `/mcp` when `NETCAP_MCP_ADMIN_TOKEN` is set. Configure your client to send the matching bearer token, and expose the endpoint only on loopback or behind authentication. The token protects MCP only. The rest of the WebUI and API follows the [hosting boundary](web-interface.md#hosting-boundary).

The stdio server starts an internal API on `127.0.0.1:60590`. If that port is taken, pick another with `-bind`. Keep it on loopback.
