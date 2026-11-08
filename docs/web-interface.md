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

Start integrations with [MCP](mcp.md) when its narrower tool contracts cover the
task. Query features and capture features have different lifetimes; changing
settings does not rewrite historical output.
