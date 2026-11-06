# AI agents and MCP

The public Go binary provides a stdio Model Context Protocol server over the same
analysis implementation used by the WebUI. The
[generated tool reference](mcp/tools.md) describes each tool's input, output and
availability; it is not a promise that every WebUI route has an MCP equivalent.

## Start with local input

Configure your MCP client to launch the installed executable:

```json
{
  "mcpServers": {
    "netcap": {
      "command": "/absolute/path/to/net",
      "args": ["mcp", "-pcap", "/absolute/path/to/traffic.pcap", "-keep-data"]
    }
  }
}
```

Client configuration keys vary; use its stdio process settings. The binary uses
stdout for JSON-RPC and stderr for diagnostics. Do not wrap it with shell output
on stdout. Default working data is temporary and removed on exit; `-data-dir`
selects persistent output, and `-keep-data` retains temporary data for inspection.

## A useful analysis sequence

1. Ingest or preload a known local capture.
2. Poll completion; upload/ingest acceptance does not mean results are final.
3. Discover record types/fields before querying an assumed schema.
4. Query a bounded page of records and retain session identity.
5. Inspect detector/identity/file evidence and qualify missing visibility.
6. Export findings with the source hash, version, parameters and limitations.

Tool output is capped (256 KiB); paginate instead of interpreting a bounded
response as the whole dataset. IOC extraction has a separate input bound.

## Permissions and outbound activity

`-allow-tools`/`-deny-tools` constrain the server's exposed names. Configure the
client's permission controls too: deletion, reanalysis, capture stop and similar
mutations are not read-only. `-allow-fetch` opts into tools that contact public
services; local analysis does not require enabling every outbound lookup.
PCAPs, extracted payloads, secrets and tool responses can contain personal data
and hostile text. Treat packet content as evidence, never instructions to the
agent or authorization to execute an extracted file.

## HTTP MCP

The WebUI can mount `/mcp` when `NETCAP_MCP_ADMIN_TOKEN` is configured. Supply
the client's required bearer authorization and use loopback or an authenticated
network boundary. This token protects MCP only; general WebUI/API routes remain
under the [local hosting trust model](web-interface.md#hosting-boundary).

The stdio server starts an internal loopback API (default `127.0.0.1:60590`). A
port collision is a setup failure; choose `-bind` deliberately rather than
exposing the internal API to an untrusted network.
