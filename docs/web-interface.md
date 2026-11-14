# Web interface

The `net` binary includes a web interface and HTTP API. Nothing else needs to run. Node and pnpm are only needed if you rebuild the interface from source.

## Choose a mode

| Mode             | Command                                                                     | What happens                                          |
| ---------------- | --------------------------------------------------------------------------- | ----------------------------------------------------- |
| One capture file | `net capture -read office-lan.pcap -out browser-audit -http 127.0.0.1:8080` | Analyses the file, then keeps serving the results     |
| Live interface   | `net capture -iface en0 -out live-audit -http 127.0.0.1:8080`               | Captures until you stop it. Needs capture privileges. |
| Upload workspace | `net capture -service -http 127.0.0.1:7070`                                 | Accepts uploads and analyses them one at a time       |

List interface names with `net util -interfaces`. In upload mode a file is accepted before it is analysed, so a successful upload does not mean the results are ready. Storage, expiry and preload settings are listed under `net capture -h`.

## Explore an analysis

| View                              | Use it to                                                                  |
| --------------------------------- | -------------------------------------------------------------------------- |
| Hosts / devices                   | See which addresses, MAC bindings and peers appeared                       |
| Connections / conversations       | See who talked to whom, in which direction, and how many bytes             |
| Protocol records                  | Read decoded fields and messages                                           |
| Files / authentication / software | Find extracted files, credentials and software versions with their records |
| Alerts / behavior                 | See which detector or baseline raised a finding                            |
| Investigation evidence            | Check capture completeness and find the records and packets behind a claim |

## Source-bound investigation workflow

Open **Investigation Evidence** (`/investigation-evidence`) to use the [analyst workspace](evidence.md#bound-analyst-workspace). A typical session on a malware capture looks like this:

1. Include the capture you are investigating as the primary capture. You can add up to seven baseline captures, for example normal traffic from the same network. Each is tied to its run ID, source file and manifest hash.
2. Search for a file hash, domain, endpoint or allowed text. The results list every match, show coverage per record type, and flag what is new compared with the baselines.
3. Open a match from a table, the graph or the timeline. You land on the exact file, frame and record. If the underlying file has changed, the lookup fails instead of silently showing another capture.
4. Save the query or a report. The saved item keeps its source bindings, snapshot, references and revision. An analyst review moves it from draft to reviewed.
5. Inspect packets or reanalyse. See [source inspection and splits](evidence.md#export-packet-evidence) and [child analysis](evidence.md#reanalyze-a-capture). The parent analysis stays available.
6. Review diagnostics. You approve a sanitised log against its digest. [Reproduction metadata](evidence.md#export-reproduction-metadata) leaves out secrets, local paths, logs and payload.

On the Records page, **Reload current capture with exact occurrence actions** enables this workflow for supported unfiltered captures that carry a Community ID. If the capability is missing, the workflow is disabled. Paging through the catalogue uses one snapshot, so start a new query after the file changes. Exported PNG and SVG charts carry their coverage labels (prefix selection, caps, schematic relationships). A chart without a `data-netcap-coverage=v1` label may be incomplete.

Pick the analysis you want before you search. A session only searches what it has loaded, not every directory on the host. While an analysis is still running, aggregates and post-processing can change the views.

## Hosting boundary

The local web interface and API trust whoever can reach them. Same-origin CORS is not authentication, and `NETCAP_MCP_ADMIN_TOKEN` only protects the HTTP MCP endpoint, not every `/api` route. Bind to loopback. If other people need access, put authentication, authorisation and network isolation in front of it.

Uploads can contain credentials, personal data, payloads and executables. Check where the output is stored and how long it is kept, and don't use real captures in public screenshots. The storage quota is not a hard disk limit, so watch the filesystem yourself.

## HTTP API discovery

The API is not documented as an OpenAPI spec. Use your browser's network tab to see the requests the interface sends and the responses it gets back.

| Route                                   | Purpose                                                                |
| --------------------------------------- | ---------------------------------------------------------------------- |
| `/api/features`                         | Current feature flags. Changes apply to later analyses only.           |
| `/api/evidence/related`                 | Records related to a given record                                      |
| `/api/flows/query`                      | Connection rankings                                                    |
| `/api/behavior`, `/api/behavior/health` | Baseline state and coverage                                            |
| `/api/alerts/stream`                    | Live alert feed, resumable after a disconnect                          |
| `/api/analyst/capabilities`             | Capabilities and limits of the catalogue and workspace                 |
| `/api/investigation/reproduction`       | Reproduction metadata export, with an optional reviewed log projection |

For integrations, start with [MCP](mcp.md). Its tools are narrower and cover most tasks. Changing a setting does not rewrite output that already exists.

The alert stream is a live feed, not a webhook queue. Resume with `Last-Event-ID` or the cursor, and handle an HTTP 409 or `gap` response before you act on the alerts. Use [durable delivery](RULES_ENGINE.md#durable-webhook-delivery) for saved, redacted notices and the [firewall admin API](APPLICATION_FIREWALL.md#identity-and-authorization) for authenticated enforcement. The hosting boundary above applies to the capture API too.
