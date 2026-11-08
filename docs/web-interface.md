# Web interface

The public Go binary embeds a React/Vite interface and HTTP API. It runs locally
without a separate Node server. Node/pnpm are needed when rebuilding its assets
from source, not to open a released binary's UI.

## Choose a mode

| Mode | Command | Lifecycle |
| --- | --- | --- |
| One input with browser | `net capture -read traffic.pcap -out browser-audit -http 127.0.0.1:8080` | Analyze then keep serving |
| Live interface | `net capture -iface en0 -out live-audit -http 127.0.0.1:8080` | Capture until stopped; requires capture privileges |
| Upload workspace | `net capture -service -http 127.0.0.1:7070` | Accept and queue uploaded analyses |

Replace interface names using `net util -interfaces`. Service storage, expiry,
preloads and helper/embedded processing have their own flags under `capture -h`.
Service analyses are queued and processed one at a time; upload acceptance is
not analysis completion.

## Explore an analysis

| View | Question |
| --- | --- |
| Hosts / devices | Which addresses, bindings and peers were observed? |
| Connections / conversations | Who communicated, which way, and with what visible bytes? |
| Protocol records | What fields/messages were decoded? |
| Files / authentication / software | Which artifacts and claims have supporting records? |
| Alerts / behavior | Which detector or approved baseline produced a finding? |
| Investigation evidence | Was capture complete enough, and which records/packets support the claim? |

## Source-bound investigation workflow

Use **Investigation Evidence** (`/investigation-evidence`) for the version 1
[analyst workspace](evidence.md#bound-analyst-workspace):

| Step | Result to retain |
| --- | --- |
| Include captures explicitly | One primary capture and up to seven declared baselines; each bound to RunID, source and manifest hashes |
| Search exact hash, domain, endpoint or allowlisted text | Every matching occurrence, per-type coverage and novelty only within the included baseline |
| Resolve a table, Graph or Timeline occurrence | Exact file/frame/ordinal reference; changed evidence fails rather than switching captures |
| Save a query or report | Original source bindings, snapshot, references and revision; explicit analyst review changes draft to reviewed |
| Inspect packets or reanalyze | [Bounded source inspection/splits](evidence.md#export-packet-evidence) and [isolated child analysis](evidence.md#reanalyze-a-capture); parent output remains available |
| Review diagnostics | Safe log projection approved against its digest; [reproduction metadata](evidence.md#export-reproduction-metadata) omits raw secrets, paths, logs and payload |

Generic Records offers **Reload current capture with exact occurrence actions**
for supported unfiltered/Community ID streams. Capability absence disables the
bound workflow. Catalogue paging retains one snapshot; a changed file requires
a new query. Chart coverage labels persist in PNG/SVG exports, including prefix
selection, caps and schematic relationships; an unlabeled legacy count is not
automatically complete (`data-netcap-coverage=v1`).

Select the intended analysis/session before querying. Data loaded in one session
is not a global search across every directory on the host. Late aggregate output
and postprocessing can change views while analysis is active.

## Hosting boundary

The general public Go WebUI/API is a local-trust interface. Same-origin CORS is
not authentication; `NETCAP_MCP_ADMIN_TOKEN` protects HTTP MCP, not every `/api`
route. Do not bind to an untrusted network and assume account/tenant isolation.
For shared access, provide external authentication, authorization and network
isolation appropriate to the actual API before exposing it.

Uploads can contain credentials, personal data, payloads and executables. Review
output/retention paths and avoid real captures in public screenshots. Advertised
storage quotas are not a guarantee of a hard global disk ceiling; monitor the
filesystem and enforce resource boundaries outside the application where needed.

## HTTP API discovery

`cmd/capture/webui/server.go` and `routes_direct.go` define the released routes.
Use browser network requests and version-pinned source to establish parameters
and response contracts; there is no blanket OpenAPI parity promise.

| Route | Purpose |
| --- | --- |
| `/api/features` | Current feature flags; capture-time changes affect subsequent analyses |
| `/api/evidence/related` | Content-bound related-record pivots |
| `/api/flows/query` | Bounded Connection rankings |
| `/api/behavior`, `/api/behavior/health` | Baseline state and coverage |
| `/api/alerts/stream` | Bounded live alert feed with reconnect/gap semantics |
| `/api/analyst/capabilities` | Versioned source-bound catalogue/workspace capabilities and limits |
| `/api/investigation/reproduction` | Metadata-only reproduction export; optional explicitly reviewed log projection |

Start integrations with [MCP](mcp.md) when its narrower tool contracts cover the
task. Query features and capture features have different lifetimes; changing
settings does not rewrite historical output.

The alert stream is a resumable observation feed, not a durable webhook queue
or authorization to block an address. Honor `Last-Event-ID`/cursor resume and
HTTP 409/`gap` responses before consuming it for automation. Use
[durable delivery](RULES_ENGINE.md#durable-webhook-delivery) for saved redacted
notices and the separate [firewall admin API](APPLICATION_FIREWALL.md#identity-and-authorization)
for authenticated enforcement operations. The local capture API hosting boundary
above still applies.
