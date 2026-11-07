# Application firewall

`cmd/netcap-firewall` serves the HTTP WAF, protocol gateways, scoped Linux packet
firewall, fleet controller and shared counters. The rootless WAF needs no capture
device or host privileges. Linux enforcement is a separate opt-in package.
Direct origin traffic bypasses the WAF; protect the origin independently.

## Scope and delivery phases

| Surface | Shipped boundary |
| --- | --- |
| HTTP | `serve`, `validate`, `healthcheck`; native expr policies and optional embedded Coraza 3.8.1 / CRS 4.25.0 |
| Messages / HTTP/3 | `serve --websocket --grpc`, optional `--http3-listen`; shipping image builds `-tags coraza,http3`; listeners remain opt-in |
| Policy ownership | File rollout, managed single-target SQLite, or explicitly enrolled external fleet; managed and fleet ownership cannot overlap |
| Shared rates | `sharedstate` plus `--shared-rate-config`; separate fixed-window guard, mutually exclusive with the native authority client |
| Native rule authority | `policy-state` plus `--policy-state-config`; scoped/revision-pinned native thresholds, sliding/distinct windows, tuples and sequences shared across data-plane replicas |
| Gateways | `gateway --protocol` supports `modbus`, `dns`, `dns-tcp`, `dns-tls`, `redis`, `postgres`, `mysql`, `smtp`, `dnp3`; explicit termination, bounded parsers |
| Linux | `network` produces NFQUEUE verdicts; `enforcer` owns finite nft leases; both require an existing named namespace and reject the default namespace |
| Decoder bridge | Full capture CLI `--firewall-policy`, `--firewall-effects-config`, `--firewall-schema`; retrospective bindings for all 220 compiled protobuf messages, not interception of completed transactions |

## Build and local verification

Run from the repository root with Go 1.27.0, Docker Compose, Helm 3, Python 3,
PyYAML, OpenSSL and kind v0.27.0 available. Store reports outside the repository.
Capture tests need libpcap headers; CI selects `nodpi,noyara` to avoid DPI/YARA dependencies.

```bash
GOWORK=off CGO_ENABLED=0 go build -tags coraza,http3 ./cmd/netcap-firewall
python3 examples/firewall/full_stack_smoke.py --binary ./netcap-firewall --output "$TMPDIR/firewall-full-stack.json"
GOWORK=off CGO_ENABLED=1 go test -race -tags coraza,http3 ./cmd/netcap-firewall ./cmd/firewall ./internal/waf ./internal/firewalltransport
docker build -f docker/firewall/Dockerfile -t netcap-firewall:0.1.0-local .
SKIP_BUILD=1 bash examples/firewall/smoke.sh
python3 docker/firewall/check-image.py
python3 examples/firewall/gateway_smoke.py ./netcap-firewall
python3 charts/netcap-firewall/tests/test_render.py
python3 charts/netcap-firewall-control/tests/test_render.py
python3 charts/netcap-enforcer/tests/test_render.py
python3 examples/firewall/enforcer_lab.py
python3 examples/firewall/network_lab.py
python3 examples/firewall/kind_smoke.py
python3 examples/firewall/cni_qualification.py --output "$TMPDIR/firewall-cni.json"
python3 examples/firewall/control_smoke.py --output "$TMPDIR/firewall-control.json"
python3 examples/firewall/postgres_ha.py --package-tests --output "$TMPDIR/firewall-postgres-ha.json"
python3 examples/firewall/policy_state_smoke.py --package-tests --output "$TMPDIR/firewall-policy-state.json"
python3 examples/firewall/restore_drill.py --output "$TMPDIR/firewall-restore.json"
python3 examples/firewall/spool_smoke.py --output "$TMPDIR/firewall-spool.json"
python3 examples/firewall/benchmark.py --rate 50 --duration 20 --output "$TMPDIR/firewall-benchmark.json"
```

`docker/firewall/Dockerfile` pins the Go image digest, builds only the standalone
binary with `CGO_ENABLED=0 GOWORK=off`, and ships `scratch` as UID/GID 10001.
`/legal/BUILD_MODULES.txt`, module license files and notices accompany the binary.
`check-image.py` checks linked Coraza/QUIC metadata and `version.http3 == true`.
The linked Postgres driver is `github.com/lib/pq v1.12.3`, with its license retained.
`version` includes `mysql`, `dnp3` and `network`; `full_stack_smoke.py` checks that inventory.
The Dockerfile-specific allowlist excludes workspaces, secrets, captures and docs.

`smoke.sh` uses a unique Compose project, validates configuration, and checks
allowed traffic plus traversal, CRS SQL injection and a denial marker arriving
after 32 KiB of chunked body. Denied markers must be absent from origin logs.
Only `127.0.0.1:${FIREWALL_PORT:-18080}` is published; the backend is on an
internal origin network. `FIREWALL_IMAGE` and `SKIP_BUILD=1` select a built image.

## Runtime and policy contract

| Configuration | Shipping default / limit |
| --- | --- |
| `listen`, `adminListen` | `:8080`, `:9090`; separate listeners |
| `upstream` | Explicit HTTP(S) origin; no credentials, path prefix, query or fragment |
| `maxBodyBytes`, `maxResponseBytes` | 67108864 each; schema accepts 1 byte through 64 MiB; response limit applies to opted-in body inspection |
| `maxBufferedBytes` | 67108864 aggregate budget; schema accepts 1 byte through 1 GiB; copies, gzip, spools, Coraza and message allocations share the budget |
| `maxConcurrent`, `bodyTimeout` | 32 and `15s`; runtime bounds 1..4096 and at most 5 minutes |
| `inspectResponse`, `corazaCRS` | `false`, `true` in examples/chart; CRS is embedded and its file audit/debug sinks are disabled |
| TLS | Paired `tlsCert`/`tlsKey`; upstream CA/name overrides require an HTTPS upstream |
| `trustedProxyCIDRs` | Empty; configure only actual ingress/LB ranges before trusting forwarded client addresses |

Bodies spill above 64 KiB into private temporary files (`internal/waf/body.go`).
The chart uses disk-backed `emptyDir`, bounded by `spool.size: 256Mi`; Compose
uses a 256 MiB tmpfs charged to the container's 256 MiB memory limit. The aggregate
64 MiB budget is admission control, not a promise that every 64 MiB request fits
with all inspection copies. Exhaustion fails closed with 503 and releases on close.

Body-dependent native policies still require the full body inside
`NativeBodyBytes`, below the 2 MiB event ceiling; they reject larger bodies rather
than inspect a truncated projection. JSON/XML/form scalar projection is bounded;
multipart files can spill independently. The demonstration Compose policy includes
a `Body` rule, so its effective native limit is smaller than the configured ceiling.
`spool_smoke.py` uses a body-independent policy for its large-file profile.

| HTTP mode | Coverage |
| --- | --- |
| Base requests | Complete bounded request before forwarding; both wire/expanded gzip bytes bounded; nesting 64, arguments/parts 1000 |
| Base responses | Status/headers checked before final headers; body/trailers stream without inspection by default |
| `inspectResponse: true` | Complete bounded response buffering; no unbounded streaming or upgrades |
| `--websocket` | Per-message gates, 1 MiB wire/expanded message bound; no WebSocket compression |
| `--grpc` | HTTP/2 message gates with identity/gzip encoding; rejected messages do not release their frame headers |
| `--http3-listen` | QUIC/TLS termination with runtime TLS certificate/key; no 0-RTT; gRPC-over-HTTP/3 is rejected |

Policies use `netcap-policy/v1`, with typed HTTP, `Network`, `TLS`, `DNS`, `Modbus`
and protocol-adapter fields (`internal/policy/model.go`). The literal traversal
example is not an encoding/canonicalization defense. Validate the exact mounted
files with `netcap-firewall validate`; Helm does not compile expressions.

## Kubernetes

`charts/netcap-firewall` requires Kubernetes 1.25+ and an explicit `upstream`.
Defaults are a two-replica file-mode Deployment, immutable content-addressed
ConfigMap and ClusterIP Service. There are no CRDs, RBAC grants or mounted service
account tokens. `0.1.0-local` denotes a local build, not a published release.

```bash
helm upgrade --install firewall charts/netcap-firewall -n firewall --create-namespace \
  --set upstream=http://backend.application.svc.cluster.local:8080 \
  --set image.repository=registry.example.org/netcap-firewall \
  --set image.digest=sha256:<reviewed-64-hex-digest> --wait --timeout 180s
```

| Feature | Values / contract |
| --- | --- |
| Rootless bounds | UID/GID 10001, all capabilities dropped, read-only root, RuntimeDefault seccomp; writable disk-backed `/tmp`, default 256Mi |
| Messages | `websocket: true`, `grpc: true` pass the actual CLI flags; both default false |
| HTTP/3 | `http3.enabled: true`, optional `http3.port` (8443); requires `tls.secretName`; adds UDP container/Service/NetworkPolicy ingress alongside TCP |
| Ingress / direct TLS | `ingress.*` and `tls.secretName`; configure an ingress-specific HTTPS backend annotation separately when the WAF terminates TLS |
| Admin | Existing bearer `adminTokenSecret.name/key` requires `adminTLS.secretName`; optional separate `adminService.enabled`; never on application Ingress |
| Probes | `/readyz` and `/livez` on admin port 9090, HTTPS when admin TLS is configured; no bearer needed for health routes |
| Origin TLS | `upstreamTLS.caSecretName` (`ca.crt`) and optional `serverName`; HTTPS upstream required |
| Shared guard | `sharedRate.configSecretName` (`config.json`, optional CA/client cert files) and `credentialsSecretName` (`tokenEnv` entries); both references required together |
| Native rule authority | `policyState.configSecretName` (`config.json`, CA/client TLS files) and `credentialsSecretName`; mounts `/etc/policy-state` read-only and passes `--policy-state-config`; rejects mixed `sharedRate` configuration |
| Fleet targets | `mode: fleet` uses a fixed-replica StatefulSet, headless target Service and per-pod cache PVC; `fleet.configSecretName` and `credentialsSecretName` required |
| Availability | File mode permits HPA/PDB; managed mode is one replica with Recreate; fleet mode rejects HPA because target enrollment is explicit |

Secret contents are never generated from plaintext token values. Secret changes
require an intentional restart; ConfigMap hashing covers only runtime/policy data.
For fleet release `targets`, mount `targets-netcap-firewall-0.json`, `…-1.json`,
etc. from the configuration Secret. Kubernetes expands `$(POD_NAME)` in the CLI
argument; each JSON must declare its own enrolled `targetID`, `tokenEnv`, scope,
controller URL and `/var/lib/netcap-firewall/agent` cache directory. `ca.crt` may
share the Secret. Replicas share the app's target-token Secret, never operator
credentials. Random Deployment pod names are not enrollment identities.

### Network boundary

`networkPolicy.enabled` requires explicit `dnsPeers`, `upstreamEgress` and actual
`ingressPeers`; empty ingress peers deny application traffic. DNS permits TCP/UDP
53. Add control-service destinations to egress when using fleet/shared rates.
The chart selects WAF pods only; install a separate origin-side policy allowing
only the WAF. Policies are additive, and a supporting CNI is required.

`cni_qualification.py` disables kind's default CNI, installs Cilium chart 1.17.2,
and proves a previously working direct-origin probe times out while allowed WAF
traffic returns 200. It checks attacker/admin isolation and restricted admission.
Metrics Server chart 3.12.2 supplies real CPU metrics for a bounded 3→4 HPA test;
its temporary 1% target is a lab setting. Both kind scripts use private kubeconfigs
and delete only their own digest-pinned Kubernetes 1.32.2 clusters.

## Policy control and replica state

`serve` exposes bearer-authenticated `/mcp` and `/api/v1/policy/*` on the admin
listener when `NETCAP_FIREWALL_ADMIN_TOKEN` is set. File/fleet policy ownership is
read-only there. `mcp --config …` is an isolated process-owner authoring session,
not a control connection to a running WAF.

| Single-target lifecycle | MCP tool |
| --- | --- |
| Capabilities / revision | `get_policy_capabilities`, `get_policy_revision` |
| Validate / stage | `check_policy_bundle`, `stage_policy_revision` |
| Compare / simulate | `diff_policy_revisions`, `explain_policy_decision` |
| Activate / rollback | `activate_policy_deployment`, `rollback_policy_deployment`; expected revision and idempotency key required |
| Successful mutation history | `query_policy_audit` |

### Managed singleton

`mode: managed` passes `--managed --state-dir /var/lib/netcap-firewall/managed`,
requires one replica, disables HPA and sets Recreate. A retained ReadWriteOnce PVC
or `managed.existingClaim` supplies storage; UID 10001 creates a private 0700
subdirectory, preserved by `fsGroupChangePolicy: OnRootMismatch`. First bootstrap
imports the file policy; subsequent Helm changes do not replace SQLite activation.
`kind_smoke.py` qualifies TLS API activation, PVC restart recovery and rollback.

### Fleet and shared services

`charts/netcap-firewall-control` is disabled by default. Install one release per
service with `enabled=true`, `service=fleet-controller|sharedstate|policy-state`, existing
`configSecretName`, `credentialsSecretName`, and `tlsSecretName`. Both backends
use rootless TLS ClusterIP port 9092. TCP readiness proves a listening socket;
authoritative API/guard probes additionally verify database availability.

| `persistence.backend` | Control chart contract |
| --- | --- |
| `sqlite` (default) | `replicaCount: 1` only, Recreate, retained PVC; bootstrap `stateDir: /var/lib/control/state` |
| `postgres` | `replicaCount >= 2`, RollingUpdate, no local state mount/PVC; requires external database URL environment reference and dedicated schema namespace |

Postgres values declare `persistence.postgres.databaseURLEnv` and
`databaseNamespace`; they must match the authoritative bootstrap Secret's JSON
fields. `credentialsSecretName` supplies the URL environment key; **no database
URL or password belongs in Helm values**. PostgreSQL bootstrap omits `stateDir`;
the CLI rejects mixed SQLite/Postgres configuration and literal `databaseURL`.
All replicas of one service share a namespace and identical bootstrap identities;
fleet and counters use distinct namespaces. Non-loopback DB URLs require
`sslmode=verify-full`; mount the CA alongside bootstrap JSON. The chart declares
the expected environment key/namespace but cannot inspect a Secret during offline rendering.

```bash
helm upgrade --install fleet charts/netcap-firewall-control -n firewall \
  --set enabled=true --set service=fleet-controller --set persistence.backend=postgres \
  --set replicaCount=2 --set configSecretName=fleet-bootstrap \
  --set credentialsSecretName=fleet-credentials --set tlsSecretName=fleet-tls \
  --set persistence.postgres.databaseURLEnv=CONTROL_DATABASE_URL \
  --set persistence.postgres.databaseNamespace=ncf_fleet --wait
```

Controller bootstrap explicitly lists scoped `identities` and `targets`.
Shared-state bootstrap lists scoped `principals`. Agent/rate JSON durations are
integer nanoseconds, not duration strings. A shared guard example is:

```json
{"url":"https://sc-control:9092","tokenEnv":"STATE_TOKEN","ca":"/etc/shared-rate/ca.crt","window":3600000000000,"limit":3,"group_by":"Path","id":"app-rate","unit":"request"}
```

The fleet REST read URL is `https://fc-control:9092/api/v1/fleet/status?tenant=lab&app=example`
for the example Helm release. Other reads are GET `audit` and `capabilities`
under `/api/v1/fleet/`. Scoped identities may
omit their bound scope. Writes are POST `stage`, `rollout`, `activate`, `promote`,
`rollback`, `drain`, `revoke`, `resume`. Targets use GET `desired` and POST `ack`;
their attachment identity is derived from the bearer, never a query parameter.
Rollouts CAS per-target generations and wait for observed acknowledgments; they
are not atomic fleet-wide cutovers. Native thresholds/sequences are local by
default; `--policy-state-config` instead evaluates them at the authority below.
The external shared-rate guard remains a separate fixed-window feature.

### Distributed native rule state

`policy-state-bootstrap.json`, `policy-state-client.json` and the corresponding
`policy-state-values.yaml` / `policy-state-waf-values.yaml` show the exact strict
JSON and Secret-reference contracts. Install the control example as release
`native` so the client URL `https://native-control:9092` matches its Service.
Bootstrap accepts `principals`, `allowEffects`, `maxRevisions`, `maxStateBytes`
and either private `stateDir` or `databaseURLEnv`/`databaseNamespace`; unlike fleet
bootstrap it does not accept `identities`/`targets`, or shared-rate `maxKeys`.
Authority credentials contain DB URL/principal tokens; caller credentials contain
only their `tokenEnv`. SQLite uses one fenced WAL owner; PG replicas share one
dedicated namespace and identical principals, limits and effect-admission settings.

Client JSON accepts `url`, `tokenEnv`, `ca`, optional `cert`/`key`, and integer
nanosecond `requestTimeout` (default 5s, maximum 10s). The example selects 1s.
Time windows use the authority's clock, with the PG database clock and a persisted
monotonic watermark; callers cannot provide a clock. New revisions have independent
state, not a global reset; rolling back/rejoining a retained revision can resume
its live windows. Process restart does not reset committed native state.

`policy-state` health is authenticated GET `/api/v1/policy-state/health`, not the
fleet `/health` route. Optional `healthProbe.enabled` adds a pinned rootless curl
sidecar: `authorizationSecretName` holds a complete `Authorization: Bearer …` line
under key `authorization`; `caSecretName` holds `ca.crt`. It verifies TLS using the
Service name (or `serverName`) but connects to this pod's loopback, and requires
HTTP 200. The example has a separate health principal. Without this option the
control chart retains its socket-only probe; WAF readiness still uses authenticated
authority probes whenever the native client is configured.

HTTP/gateway events, WebSocket/gRPC messages and network packets incur a remote
evaluation and transactional state cost; this is not a line-rate/capacity claim.
Timeout, overload, unavailable/ambiguous commit or authority loss fail closed,
with no local fallback or automatic evaluation retry. Network mode additionally
requires `failure-verdict=deny`, no missing-listener bypass and no overflow
fail-open; size the RPC timeout and queue deadline for the deployment's latency.
Both WAF and network enforcer charts accept the Secret-reference client settings.

The authority receives projected events, including bounded HTTP bodies/headers,
in plaintext inside the trusted process after TLS termination. SQL retains scoped
policy artifacts, state digests and timing metadata, not raw per-event bodies or
datagrams. Group hashes are not a promise of anonymity. Effect policies require
both authority `allowEffects` and the caller's explicit broker admission. The direct
capture audit bridge remains retrospective; these runtime flags do not make it
inline prevention or automatically wire its observer to the authority.

```bash
python3 examples/firewall/control_smoke.py --output "$TMPDIR/firewall-control.json"
```

The runner generates private per-role env files and short-lived TLS under a
temporary directory, starts `control-compose.yaml` with two explicitly enrolled
WAFs, and proves scoped policy push plus a shared three-request limit. It stops
each control owner, runs the real `backup`/`restore` CLI into new directories,
and verifies retained generations/counters. `control_k8s.py`, invoked by the CNI
lab, tests SQLite control releases and a two-target StatefulSet under restricted
admission, including stable identity/policy after pod replacement.

`control-postgres-compose.yaml` and `postgres_ha.py` qualify Postgres-backed HA:
two fleet replicas, two counter replicas, TLS-passthrough frontend and two fixed
target agents. Generated DB passwords, DSNs and role tokens pass only through
subprocess/container environment; no credential env files are written. The runner verifies the pinned
Postgres 17.11 digest and running version, crosses replicas for stage/rollout/
activation and counters, then kills one replica of each service while leaving the
DB running. A separate DB kill/restart checks fail-closed readiness and WAL-backed
generation/counter preservation. `--package-tests` runs the real Postgres race,
multi-process, CAS and crash tests using `NETCAP_POSTGRES_TEST_URL` and the uniquely
labeled loopback `NETCAP_POSTGRES_TEST_CONTAINER`. No existing database is targeted.

### Backup and restore drill

| Store | Operator path |
| --- | --- |
| SQLite control services | Stop/fence the old owner; select `--service fleet`, `sharedstate` or `policy-state` for `netcap-firewall backup --config … --output /absolute/private/snapshot.sqlite`; restore into a new empty StateDir |
| Postgres control services | Optional schema-dump/Restic CronJob below; database-operator roles/WAL/PITR and restore procedure remain separate; SQLite backup CLI rejects Postgres |
| Managed policycontrol | `managed_snapshot.py` with `backup` or `restore`, `--state-dir /absolute/state --snapshot /absolute/private/snapshot.sqlite`; Python SQLite backup API uses the same lifetime ownership lock |

Snapshots contain sensitive revisions/audit/counters and use private directories
and 0600 files. Restore requires an empty destination and does not fence another
host automatically. SQLite is one authoritative owner. Postgres permits active-active
application replicas against one writable primary; **primary election, fencing,
replication durability and DB failover are database-operator responsibilities**.
`restore_drill.py` checks managed live-owner/corrupt/existing-destination refusal,
then restored revision/audit/idempotency receipts and deny→rollback→allow traffic.
`control_smoke.py` separately checks SQLite fleet/shared-state CLI recovery.

### Scheduled Postgres backups

`charts/netcap-firewall-control` adds no backup resources by default. Enable
`backup.enabled` only with Postgres, Kubernetes 1.27+, a unique cluster/operator
`backup.scope` and pre-provisioned Secrets. `examples/firewall/backup-values.yaml`
shows the opt-in values; it contains no repository URL or credentials.

| Backup input / bound | Contract |
| --- | --- |
| `backup.databaseSecretName` | `pg_service.conf` with service `[backup]`, host/port/dbname/user/password and `sslrootcert=/db/ca.crt`; include `ca.crt` in that Secret. `pg_dump` forces `sslmode=verify-full`; no password/DSN in argv |
| `backup.repositorySecretName` | `RESTIC_REPOSITORY` and backend-auth environment entries; optional config/CA files mount read-only at `/repository`, with `ca.crt` used automatically. Keep authentication out of the repository URI |
| `backup.passwordSecretName` | Separate Restic password file, key `password` unless `passwordSecretKey` overrides it; repository must already be initialized by its operator |
| Dump stage | Digest-pinned Postgres 17.11 `pg_dump`, consistent custom-format archive of the configured service schema; 64 MiB default hard file limit, 5s lock wait, private 0600 files; failed/oversize dumps never become upload inputs |
| Encryption stage | Separate digest-pinned Restic 0.18.1 image; no runtime installer, repository initialization, Kubernetes API mutation or application pause |
| Retention | Daily 7 / weekly 4 / monthly 3; forget always selects both stable host and tag, including scope/namespace/release/service. `prune: false` by default; optional prune performs repository-wide unreferenced-blob GC after scoped forget |
| Job bounds | Forbid overlap, 900s deadline, one retry, 3600s finished-Job TTL; rootless 10001, dropped capabilities, read-only root, no service-account token; bounded work/cache volumes and ephemeral-storage limits |

Backups cover all tenants in that service schema, not a tenant-scoped API export.
Repository provisioning, access policy, key rotation and backup-success alerting
remain operator work. Logical snapshot retention does not bound physical repository
bytes while prune is disabled. Work holds plaintext only in the private ephemeral
volume; the upload stage removes the archive on ordinary exit, with pod/Job cleanup
covering failed startup or forced termination. No automatic SQLite stop/scale procedure is installed.

```bash
helm upgrade --install fleet charts/netcap-firewall-control -n firewall -f examples/firewall/backup-values.yaml
python3 examples/firewall/postgres_ha.py --backup-restore --output "$TMPDIR/firewall-backup.json"
```

The local drill runs the exact chart scripts against a disposable encrypted Docker
volume, verifies restored fleet generation/counter values, refuses bad CA/password
and oversize dumps, and preserves foreign host/tag snapshots through scoped prune.
Restic networking is disabled in the drill. Off-host delivery and production
schedule execution require separate qualification; no estate/cloud resources were used.
The local drill passes `PGPASSWORD` through process environment and pipes the
Restic password into container tmpfs. Both PostgreSQL/backup runners check their
host fixture directories for generated password/token leakage; only non-secret
connection settings and TLS certificate/key fixtures remain in those directories.

## Protocol gateways and optional enforcer

`redirect` places an already-running TCP message gateway on an explicitly scoped
routed service path. Start the gateway inside its named namespace, then install
the redirect from outside it:

```bash
ip netns exec firewall-router netcap-firewall gateway --protocol redis \
  --listen 10.90.0.1:16379 --upstream 10.91.0.2:6379 \
  --allow-client 10.90.0.0/24 --policy /etc/netcap-firewall/redis.yaml
# Separate process; SIGTERM removes only this redirect's owned table.
netcap-firewall redirect --namespace firewall-router --interface g0 \
  --service-cidr 10.91.0.2/32 --service-port 6379 --gateway-port 16379 \
  --protocol redis --tls-mode plaintext
```

The gateway must be listening before activation. `--tls-mode terminated` records
an operator assertion; the gateway still needs its TLS certificates and explicit
termination configuration. Opaque TLS is rejected. Placement applies to new
conntrack sessions and one configured fixed upstream. `transparent_lab.py`
verifies real shipping Redis/DNP3 gateways and redirect processes on IPv4/IPv6,
source identity, denial before origin receipt, management exemptions, and SIGTERM
cleanup, without changing the default namespace.

| Example under `examples/firewall/` | Contract |
| --- | --- |
| `network-policy.yaml` | Default-deny packet policy with explicit `Protocol == "network"`, bidirectional service selectors, visible-SNI denial and an explicit allow for unclassified TCP/443 |
| `advanced-policy.yaml` | Sliding counts, distinct paths/ports, grouping tuples and a named login→export sequence; local by default, or authoritative per scope/revision with `--policy-state-config` |
| `effects-policy.yaml`, `effects-config.json` | HTTP-path or SMTP-RCPT denial emits a bounded `block_source` intent; operator bootstrap fixes HTTPS endpoint, `LAB_ENFORCER_TOKEN`, CA and future TCP/8080 scope; no policy-supplied endpoint |
| `audit-smb-policy.yaml` | `Protocol == "audit"`, `RecordType == "SMB"`, `Fields["ShareName"] == "ADMIN$"`; only an explicitly admitted live capture can request a future lease |

For packet mode select `--inspect-tls`. `TLS.Encrypted` indicates available visible
ClientHello metadata; false is unknown, including SYN/incomplete/missing metadata,
not proof of plaintext. The example allows that unknown case so handshakes can
progress. ECH can hide the real SNI; no rule here decrypts application payloads.
`effects-config.json` expects `lab-enforcer.crt` in the process working directory
and a TLS enforcer at `127.0.0.1:19091`; JSON `retention` uses nanoseconds. Its fixed lease destination is
`198.51.100.0/24`, interface `lab0`, forward/TCP/8080, protected `192.0.2.0/24`.
The SMTP trigger requests that same future scope, not a global or SMTP-wide ban.

`full_stack_smoke.py` compiles these exact files with the CLI, verifies effect
policies are rejected without broker admission, and reuses existing integration
tests: `TestEffectsBrokerShippingDryRunLease` proves trusted-proxy HTTP traffic
creates an actual TLS-authenticated dry-run lease; `TestLiveBrokerAndReplayAreSeparated`
and `TestCaptureMultiFileReplayNeverContactsEnforcer` prove native audit/live/replay
boundaries. It generates temporary CA/token material and changes no host rules.
SMTP is compiled here; this runner does not claim SMTP effect-traffic qualification.

Gateway defaults are 64 connections, 1 MiB messages, 5-second IO and 5-minute
sessions, with `--max-state-entries=128`; inspect `gateway --help` for explicit client/
upstream TLS flags. `gateway_smoke.py` provides origin-evidence fixtures for the
DNS/Modbus examples. Additional bounded parsers are in `internal/gateway`; their
existence does not imply support for every protocol extension. Modbus
writes must be denied in the request phase; response denial cannot undo a write.

| Additional gateway | Covered profile / exclusions |
| --- | --- |
| MySQL | Protocol 4.1 auth relay and independently negotiated TLS legs; QUERY/INIT_DB/PING and bounded prepared-statement lifecycle; query metadata gates execution. Rejects multipart 0xffffff packets, compression, LOCAL INFILE, multi-results, long-data/cursors and unsupported capabilities (`mysql_wire.go`, `mysql.go`) |
| DNP3 | CRC-validated link frames, confirmed/unconfirmed transport, sequence-bounded reassembly and explicit object profiles for READ/WRITE/SELECT/OPERATE/restart functions. One request APDU per authorization, configured message/state bounds; unsolicited and unknown profiles rejected (`dnp3_wire.go`, `dnp3.go`) |

### Decoder audit bridge

The full `net` capture binary accepts `capture --firewall-schema` to enumerate the
versioned registry of all 220 compiled protobuf message types, field sensitivity
and projection bounds. `capture --read fixture.pcap --firewall-policy examples/firewall/capture-policy.yaml`
evaluates existing decoder records retrospectively; replay never contacts an
enforcer. Live `--iface` additionally requires explicit `--firewall-effects-config`
to admit source-attributed, bounded future response actions. Service/upload mode
is unsupported. Existing record rules bind through `RecordType`, typed `Fields`
and `audit.schema_version`; a retrospective `deny` is an observation, not a packet
drop. This does not turn all 220 decoder bindings into inline prevention.
Projection bounds are 128 fields, 1024 bytes/value, four collection entries,
depth six and 4096 traversal nodes (`internal/firewallaudit/schema.go`).

`enforcer` provides bearer-protected `/v1/leases` and `/mcp`, at most 1000 leases
and 15-minute TTL. Select `--dry-run` explicitly for previews; its CLI default is
live. The canonical shared `/run/netcap-enforcer` lock coordinates namespace/table
ownership. Named namespace inode checks reject current/default namespace aliases.

### Enforcer package

`docker/enforcer/Dockerfile` pins Alpine 3.23.2, `iproute2-minimal=6.17.0-r0` and
`nftables=1.1.5-r2`; BusyBox supplies `nsenter`. Installed package versions and Go
licenses are retained. Default `--help` is inert; live scope must be explicit.

| `charts/netcap-enforcer` | Contract |
| --- | --- |
| Enablement | Disabled by default; dedicated lab `nodeSelector` and existing named namespace/interface required |
| Root privileges | Drop all, add only NET_ADMIN/SYS_ADMIN; no blanket privileged mode; read-only root; seccomp/AppArmor Unconfined for setns/unshare/mount |
| Host visibility | Host network makes default-namespace identity checks cover the node network; private PID namespace avoids host PID 1 access |
| Mounts | Existing `/run/netns` read-only/HostToContainer, shared private `/run/netcap-enforcer`, node-local state directory; creates no host namespace or route |
| `mode: leases` | Existing bearer Secret; explicit destination/protocol/port; loopback API only, no Service/Ingress |
| `mode: network` | Explicit `scope.protectedCIDRs` select protected traffic; optional management exemptions; immutable policy ConfigMap; queue/deadline/failure/TLS-metadata values map to actual CLI flags |
| Native network authority | `policyState` Secret references pass the client config; renderer and CLI reject fail-open queue/deadline settings when it is enabled |
| Network failure policy | Queue 100, length 1024, deadline 100ms, failure verdict deny; no-listener bypass and overflow fail-open default false |
| Updates | OnDelete requires deliberate pod replacement; network table is fixed by the runtime; lease table remains independently scoped |

`network_lab.py` runs `TestRoutedLab` and the standalone network CLI against
disposable named client/router/origin namespaces: 8080 allowed, 8081 dropped,
traffic restored on shutdown. Both network/enforcer runners reject skipped or
missing required tests and compare the default namespace nft ruleset before/after.
They have no host mounts; NET_RAW is added only to the crafted-packet test fixture.
The CNI lab also starts both DaemonSet modes against an existing named lab namespace.

### Infrastructure qualification

| Evidence runner | Verified boundary |
| --- | --- |
| `kind_smoke.py` | File install/upgrade/Helm rollback; managed TLS activation, PVC restart, policy rollback |
| `cni_qualification.py` | Cilium origin/client/admin isolation, restricted admission, local counters, real HPA 3→4, optional enforcer modes, both control charts and stable fleet targets |
| `control_smoke.py` | Scoped TLS services, two-target policy push, shared count, offline fleet/state CLI recovery |
| `postgres_ha.py --package-tests` | Active-active control/counter processes, surviving application replicas, DB outage/WAL recovery and real Postgres package race/crash tests |
| `postgres_ha.py --backup-restore` | Pinned rootless dump/encryption scripts; local encrypted restore to separate databases; scoped retention/prune and negative credential/size tests; no off-host claim |
| `policy_state_smoke.py` | Two WAFs/two PG authorities; shared native sliding/distinct/sequence state, authority loss, revision isolation, authenticated health, DB outage/recovery and no raw event marker in stored state |
| `spool_smoke.py` | Three 8 MiB multipart files with CRS off and on; late-body denial absent at origin; retained-body quota exhaustion yields 503 and recovers on close; 1 CPU/256 MiB container |
| `benchmark.py` | Standard-library bounded open-loop load; offered/completed counts, generator drops/lag, scheduling-inclusive p50/p95/p99, image/config hashes and raw cgroup CPU/memory counters |

`benchmark.py --body-bytes 2097152 --rate 1 --duration 5` measures multipart file
traffic using a body-independent policy; `--no-coraza` selects the other profile.
`buffered-nginx.conf` consumes the complete body before returning success;
`X-Origin-Request-Bytes` is asserted against the offered file size. The late-body
policy is checked after load. Multipart file acceptance does not
prove file-content inspection or acceptance of arbitrary opaque bodies by CRS.
The 64 MiB runtime ceiling is not a measured production capacity guarantee.

Local qualification on 2026-11-07 used native ARM64 Docker Desktop Linux. Native
AMD64/ARM64 deployment, capture-bridge and Kubernetes jobs passed at `bbc20a6`
([run 42333924481](https://github.com/dreadl0ck/netcap/actions/runs/42333924481)).
No emulated result counts as native qualification. Reports live in `$TMPDIR`/CI artifacts, not git.

### Local sustained qualification

`examples/firewall/qualification/` supplies a loopback-only open-loop runner and
JSON receipts. Build tags are `coraza,http3,nodpi,noyara`; `runner.py` starts a
detached owned process and records its birth/command identity, binary/source
SHA-256, Go dependency versions, hardware and checkpoint. Evidence stays outside git.
The supervisor defaults to 128 bounded generator workers; raw runner `-workers`
defaults to 32. Scheduling-inclusive latency still counts generator pauses.

| Profile | Exercised wire subset |
| --- | --- |
| HTTP/1.1, H2, H3 | Native/CRS × 0/10/100/1000 filler rules: 24 profiles, each with a marker-denial rule |
| Local evaluator state | One additional HTTP profile exercises a one-second sliding window and asserts zero groups/entries after expiry/maintenance |
| WebSocket / gRPC | RFC 6455 uncompressed masked text/echo; identity unary gRPC over verified TLS H2 |
| DNS / Redis | UDP A question/compressed A answer; RESP2 SET and denied FLUSHALL |
| Postgres / MySQL | Protocol 3.0 startup/simple query; protocol-10 scripted greeting/4.1 handshake/COM_QUERY |
| Modbus / DNP3 / SMTP | TCP FC3/FC6; unconfirmed single-fragment read/CROB; EHLO/envelope/whole DATA |

The nine non-HTTP peers are owned scripted fixtures, not vendor-server version
qualification. `protocols.py` separately requires every named integration test,
every requested repetition and zero skips; these bounded tests cover additional
prepared-statement, fragmentation, replay, authentication and dependency cases.

| Local gate | Requirement |
| --- | --- |
| Load | Allowed and denied operations on all 34 profiles; zero errors, generator drops, false blocks, forbidden origin bytes/requests and forbidden fixture effects; scheduled-arrival p99 ≤2 s |
| Resources | Five-second whole-process samples: Go heap ≤1 GiB, RSS ≤2 GiB, descriptors/goroutines ≤4096, owned scratch ≤64 MiB; current/highwater/recovery plus local evaluator state are recorded |
| Lifecycle | Owned origin 503, policy reload, in-process proxy/listener restart and a changed TLS certificate SHA-256; allow/deny and released buffers are checked after recovery |
| Corpus | Calibration/held-out business routes and attack controls require exact status and independent origin deltas; critical false blocks must equal 0 |
| FTW | Immutable Apache-2.0 CRS source/license hashes; reviewed 941100 cases 2/4 over HTTP/1.1/H2/H3; four other upstream cases remain excluded |
| Negative control | `-inject-leak` sends directly to the owned origin and must exit 1; `audit.py` repeats it against the measured binary |
| Pilot | `pilot.py` accepts only a finite allowlisted local fake plan; absent production authorization is recorded as unrun, not a code failure |

```bash
go test -race -tags coraza,http3,nodpi,noyara ./examples/firewall/qualification ./internal/waf
python3 -m unittest discover -s examples/firewall/qualification -v
ROOT=$(mktemp -d "${TMPDIR:-/tmp}/netcap-qualification.XXXXXX")
go build -tags coraza,http3,nodpi,noyara -o "$ROOT/qualify" ./examples/firewall/qualification
mkdir "$ROOT/run"
python3 examples/firewall/qualification/runner.py start "$ROOT/run" --binary "$ROOT/qualify" --duration 86400 --rate 50
python3 examples/firewall/qualification/runner.py monitor "$ROOT/run"
python3 examples/firewall/qualification/runner.py resume "$ROOT/run"
python3 examples/firewall/qualification/runner.py stop "$ROOT/run"
```

`resume` observes the same verified process/checkpoint; it never credits downtime
or relaunches a dead process. `stop` refuses an unverified owner. A 24-hour request
does not establish 24-hour evidence: only a completed `soak_24h_pass: true` does.
OS-process/external-state disruptions under sustained load, vendor-server matrices
and external UDP ingress/LB/NAT/CNI paths remain separate gates.

The measured baseline password false positive was CRS `942100`. Qualification
uses exactly `crsTargetExclusions: [{path: /api/account, method: POST, argument:
password, ruleID: 942100}]`; the original password case is calibration and a new
password case remains held out. `coraza_exclusions_test.go` checks that XSS on
that field, other fields/routes/methods and native denials remain enforced.
Exclusions accept at most 32 literal scopes and only application-attack rule IDs.

For shorter evidence use `--duration 1800`; direct `-quick -mixed -duration 30s`
is a quick check. Run `-ftw-only`, `protocols.py --repetitions 2` and
`pilot.py --execute-local-fake` into fresh evidence directories, then join them
with `audit.py --run R --ftw F --protocols P --pilot L --output A`.
`qualification.json` distinguishes the local pass from every unrun deployment gate.

The native ARM64 sample on Apple M5 Max/Go 1.27.0 completed 1,800 seconds at
50 offers/s with 128 workers: 90,000 offers across 34 profiles, 71,980 allowed,
18,020 denied, zero errors/drops/false blocks/forbidden origin bytes or fixture
effects. All 179 fault cycles recovered; maximum profile p99 was bounded by
256 ms. The 288 corpus rows and six FTW wire cases passed with zero protocol
skips. `topic-owned-final-audit/qualification.json` records the joined local pass;
the load receipt SHA-256 is `1915bf55ce55bcca6a23cbc0c478b3e4c98f316f0f5e103a980a61bde2c2123e`.
This is 30-minute evidence; `soak_24h_pass` remains false.

## Rollout and rollback

### Versioned release candidates

`.github/workflows/firewall-release.yml` builds independent firewall candidates;
`.goreleaser-firewall.yml` disables GoReleaser publication. The existing
`.goreleaser.yml` and main Netcap release workflow retain their own release path.
`firewall-v<SemVer>` is the firewall tag namespace. No script creates a tag,
GitHub release or PR, or changes a cluster.

| Artifact / gate | Contract |
| --- | --- |
| Trust policy | `scripts/firewall-release-policy.json`: issuer, exact workflow/tag identity, supported config/policy schemas, pinned tools, required qualifications and 3 external review slots |
| Native build | `firewall_release_build.py native`: clean committed checkout; native Linux runner and matching Docker architecture; GoReleaser WAF (`coraza,http3`) and enforcer binaries copied into release Dockerfiles once |
| Version evidence | `version` retains config/policy versions and adds `releaseVersion` / `commit`; `version-smoke` checks both runtime images, embedded version/commit and HTTP/3 build feature |
| Qualification | Each named policy qualification has a hashed log per architecture; Linux amd64 and arm64 receipts bind the same source commit/version to the shipped image digests; lab overlays add test tools and retain the shipped binary bytes |
| Final candidate soak | `assemble --qualification-run <run>` validates a completed 24h mixed run, copies hashed receipts and binds them to both index digests. Publication rejects missing soak evidence, old commits, dirty binaries and changed before/after inputs. `check-qualification <run> --commit <full-SHA>` checks eligibility without publication |
| Images | OCI layouts preserve platform manifests; assembly creates 2 indexes containing exactly the tested amd64/arm64 children; promotion uses `crane copy`, never rebuilds |
| Helm 3 | Packages all 3 charts with matching `version`, `appVersion`, image tag, repository and index digest; lint/render precede packaging; OCI promotion preserves the chart manifest digest |
| Offline assets | Each architecture includes binaries, OCI archives, pinned Syft SPDX, source/license inventory and corresponding-source export; source includes the committed tree, vendored Go modules and Go toolchain source; checksum/signature bundles cover the complete directory |
| Source inventory | Every SPDX package needs a resolved license plus hashed license text and source export. Missing Alpine/base-image sources or unresolved Go licenses block validation; `blockers.json` lists supplemental work. `supplements.json` maps `name@version` to `license`, `source` and `licenseFile` paths beneath its own directory |
| Signatures | Opt-in publication uses cosign keyless, exact GitHub OIDC issuer and workflow/tag identity; SLSA v1 predicates bind commit/version and digest, without claiming a SLSA assurance level. Per-platform SPDX is attested separately |
| Offline verification | `firewall_release.py verify` checks candidate/checksum signatures, all files, archive blob hashes/platform/labels/binary bytes, chart metadata, OCI chart layer hashes and all 9 signed provenance subjects. Supply an independently pinned Sigstore trusted root; never trust a root merely because it accompanies a download |
| Rehearsal | `make firewall-release-rehearsal` creates isolated loopback registry fixtures, temporary keys and a no-services signing config; copies 4 image manifests, 2 indexes and 3 charts to another local repository and verifies signatures/attestations. Fixture receipts say `qualificationMode: rehearsal`, `native: false`; publication and ordinary release verification reject them |

Install the policy-pinned tools into an external directory, placing it first on
`PATH`. `firewall_release_tools.py` downloads Syft, GoReleaser and Helm from
their upstream release endpoints and checks upstream SHA256 files. Install
crane/cosign with the exact Go module versions in the JSON policy. Current pins
were checked against official GitHub releases and Helm's distribution endpoint
on 2026-11-07; action commit pins match their official version refs.

```bash
make firewall-release-test
make firewall-release-rehearsal
make firewall-release-build FIREWALL_RELEASE_VERSION=0.1.0-rc.1 FIREWALL_RELEASE_OUTPUT="$TMPDIR/firewall-build"
# On each native Linux architecture; start a loopback-only registry first.
python3 scripts/firewall_release_build.py native --version 0.1.0-rc.1 --arch arm64 --output "$TMPDIR/candidate/arm64"
# Combine both architecture directories under one candidate root.
python3 scripts/firewall_release_build.py assemble --version 0.1.0-rc.1 --output "$TMPDIR/candidate"
python3 scripts/firewall_release.py validate "$TMPDIR/candidate"
# Published bundle verification uses no registry; root is provisioned independently.
python3 scripts/firewall_release.py verify ./candidate --offline --trust-root /trusted/sigstore-root.json
```

**Publication requires a separate manual decision.** PRs, tag pushes and the
default `workflow_dispatch` produce candidates and loopback rehearsals only.
The `publish` job requires `dryRun: false`, a matching existing firewall tag,
matching commit and approval of the `firewall-release` environment. Configure
that environment with required human reviewers and tag restrictions before use.
Set `candidateRun` to the successful same-commit manual/tag candidate run and
`inputsRun` to the review artifact run. The publication dispatch skips native
builds/assembly, authenticates the candidate run's repository/workflow/commit,
verifies its rehearsal bundle, attaches digest-bound reviews, then signs and
copies those exact artifacts. A PR run cannot be used as a publication candidate.

| Manual release input | Required evidence |
| --- | --- |
| Native qualification | Successful same-commit Linux amd64/arm64 receipts; emulated or synthetic tests cannot satisfy this gate |
| Soak input | `firewall-release-inputs/qualification/` contains `manifest.json` and all named receipts from the final clean merged commit. Build the runner with VCS stamping enabled; keep source and binary unchanged until completion. The pre-UI `b2b72450` run cannot qualify a later candidate |
| External reviews | `security`, `license-and-corresponding-source`, `operations`; each needs `decision: approved`, identified reviewer, HTTPS review URI, hashed evidence file, matching commit/version and both index digests; generated slots remain `pending` |
| Input transport | Same-repository `inputsRun` artifact named `firewall-release-inputs`; native jobs optionally read supplements; publication requires `reviews.json` and its hashed evidence files, copied by `apply-reviews` after verification of the original bundle |
| Registry authorization | Publication job alone gets `packages: write` / `id-token: write`, with `contents: read`; optional short-lived `FIREWALL_REGISTRY_TOKEN` must be scoped to the intended repository/packages, otherwise job-scoped `GITHUB_TOKEN`; no contents write or repository-wide PAT |
| Release storage | Upload-artifact bundles are retained for 30/90 days; an operator must retain the approved offline bundle and independently pinned trust root in durable release storage |

There is no external approval or production qualification supplied by the local
rehearsal. `candidate-checklist.json` reports `publicationApproved: false`.

`scripts/firewall-integration-gates.json` records branch dependencies and external
gates. The qualification runner requires `waf.Config.CRSTargetExclusions` and
`waf.CRSTargetExclusion` from the web integration branch (`41535d61`); until that
merge, its Go build fails rather than substituting an exception stub. The bounded
pilot CLI remains local-only because no production target authorization exists.

### Verified upgrade planning

`scripts/firewall_release.py plan-upgrade` verifies both signed offline manifests
before creating a mode-0600 state archive. It rejects unsupported config/policy
schema versions, config/policy files outside the backup tree, symlinks, existing
backup/output files and implicit downgrades. Configuration validation and Helm
diff remain operator gates; the planner executes only fixed verification tools,
never deployment commands or manifest-supplied commands.

```bash
# Stop/quiesce writers first; include configuration, policy and consistent state.
python3 scripts/firewall_release.py plan-upgrade \
  --current ./current --candidate ./candidate --offline --trust-root /trusted/sigstore-root.json \
  --state /private/firewall-state --config /private/firewall-state/config.yaml \
  --policy /private/firewall-state/policy.yaml --backup /private/backups/pre-upgrade.tar.gz \
  --output /private/backups/upgrade-plan.json --quiesced
```

For rollback, select the previous signed bundle as `--candidate` and add
`--allow-downgrade`. The plan records source/target manifest hashes, exact image
digests, schemas, configuration/policy hashes and backup hash; it never changes
live state. Validate a restore and use the deployment-specific procedure below.

| Step | Check |
| --- | --- |
| Prepare | Build shipping tags, validate exact configuration/policy, review image digest and Secret bootstrap identities |
| Preview | Helm schema/render tests, Compose origin-evidence checks, dedicated CNI/control qualification |
| Route | Ingress only to WAF; separate origin policy; allowed and denied traffic with origin evidence |
| Observe | Private readiness/metrics and bounded redacted audit; shared-guard/fleet readiness is a dependency boundary |
| File rollback | `helm rollback firewall <revision> -n firewall --wait`; recheck traffic; rolling pods can briefly serve different revisions |
| Managed rollback | Single-target policy API restores SQLite activation; Helm rollback does not restore managed state |
| Fleet rollback | Controller rollback with expected job phase/generations; verify acknowledgments and live target traffic |

No mode automatically routes clients directly to the origin on WAF failure.
Retain prior image digests, values and consistent state snapshots.

## Deferred roadmap

| Remaining gate | Exact boundary |
| --- | --- |
| Production qualification | Passing native/cluster CI does not qualify another CNI, storage provider, traffic mix or external HTTP/3 UDP ingress/LB/NAT path |
| HA / state loss | SQLite remains singleton; Postgres application replicas are active-active, but primary fencing and DB HA remain database-operator responsibilities; stale-snapshot recovery is not lossless |
| Distributed semantics | Native thresholds/sequences are authoritative when configured; default local mode and the separate fixed-window guard retain their documented semantics; fleet acknowledgments are not an atomic cutover |
| Protocol extensions | No encrypted passthrough payload decryption, WebSocket compression or gRPC-over-HTTP/3; gateway parsers cover explicit subsets |
| Storage / capacity | Optional PG schema backup/encrypted upload/scoped retention is implemented; production repository provisioning, off-host restore/schedule qualification, SQLite offline automation and deployment-specific sizing remain; 64 MiB bounds do not establish throughput |

## Verification pitfalls

| Symptom | Correction |
| --- | --- |
| Helm 3.8 templates as Kubernetes 1.23 | Pass `--kube-version 1.25.0` or newer; do not count version rejection as a schema negative test |
| Compose says `invalid mount path: nodev` | Quote the entire comma-containing tmpfs string in flow lists |
| Client gets 403 but origin saw the request | Require origin-log evidence, as `smoke.sh` does |
| kind import fails on fixture archive | Pull the digest-pinned backend in-cluster; load only locally built application images |
| Managed StateDir is not 0700 | Use a private subdirectory beneath the PVC mount and preserve ownership across mounts |
| Enforcer cannot stat host PID 1 namespace | Keep private PID visibility; host networking already identifies the node default network without SYS_PTRACE |
| `rollout status` rejects OnDelete | Delete the selected pod deliberately, wait for its replacement and verify the actual API/table |
| Large-file test gets origin 413 | Raise the lab nginx `client_max_body_size`; its default is independent of WAF limits |
| CRS rejects opaque upload fixture | Use an explicitly typed multipart fixture for file-spooling qualification; do not report it as arbitrary opaque-body or file-content inspection |
| Postgres crash test interrupts another package | Run the two PG packages with `-p 1` against their shared disposable DB; concurrency inside each test remains enabled |
| Default-deny routed policy breaks allowed TCP | Match protected service replies explicitly; NFQUEUE covers both directions, not only client destination ports |
| CodeQL `py/clear-text-storage-sensitive-data` on PG fixture env files | Keep generated DB passwords/DSNs in process environment; Restic's local fixture password file belongs only in container tmpfs, populated through stdin |
| cosign v3 rejects `--offline` on `verify-blob` | Supply the independently pinned `--trusted-root` and complete v3 bundles; that command has no `--offline` flag |
| Syft SPDX creator index 0 is an organization | Match the exact `Tool: syft-<pinned version>` entry anywhere in `creationInfo.creators` |
| Helm 3.22 schema diagnostics use `/runtime/field` | Negative render tests accept slash or dot field paths while still requiring schema rejection |
| BuildKit adds unknown-platform attestation children | Release runtime builds disable BuildKit provenance/SBOM; the release pipeline creates its own verified cosign/Syft attestations after qualification |
