# Application firewall

Community Core starts with an inline HTTP reverse proxy: `cmd/netcap-firewall`,
`internal/waf`, and the versioned `internal/policy` evaluator. Deploy the
firewall between clients and an HTTP origin; traffic sent directly to the
origin is outside this boundary. `internal/firewall` host-response actions are
a separate integration; this deployment needs no packet-capture device,
`NET_ADMIN`, `NET_RAW`, host network, or host firewall changes.

## Scope and delivery phases

| Phase | Boundary and acceptance |
| --- | --- |
| Community Core WAF | `serve`, `validate`, and `healthcheck`; full request inspection before forwarding; native expr policy plus embedded Coraza 3.8.1 / CRS 4.25.0 with `-tags coraza` and `corazaCRS: true` |
| Policy control | `serve --managed --state-dir …` attaches authenticated HTTP/MCP control to that same running WAF; SQLite persists revisions, activation, receipts, and successful mutation audit |
| Deployment | Rootless image, chart, Compose smoke, and kind install/traffic/upgrade/rollback checks in `.github/workflows/firewall.yml` |
| Protocol gateways | Explicit plaintext Modbus TCP and classic DNS UDP termination via `gateway`; policy examples in `examples/firewall/` |
| Deferred | Fleet coordination/controller, distributed thresholds, HTTP/3, arbitrary routed TCP/UDP interception, TLS passthrough payload inspection, and mail protocol enforcement |

The example native policy has 2 demonstration rules; Coraza CRS is also enabled
in `examples/firewall/config.yaml` and chart defaults.
`Path contains ".."` is a literal traversal example, not a canonicalization or
encoding defense. There is no measured line-rate or production-throughput claim.
Exercise application-specific encodings, uploads, streaming, upgrades, and
timeouts before routing those workloads through the proxy.

## Build and local verification

Run from the repository root with Go 1.27.0, Docker Compose, Helm 3, Python 3,
and PyYAML installed:

```bash
GOWORK=off CGO_ENABLED=0 go build -tags coraza ./cmd/netcap-firewall
GOWORK=off CGO_ENABLED=1 go test -race -tags coraza ./cmd/netcap-firewall ./cmd/firewall ./internal/waf ./internal/policy ./internal/policycontrol ./internal/gateway ./internal/enforcer
docker build -f docker/firewall/Dockerfile -t netcap-firewall:0.1.0-local .
docker compose -f examples/firewall/compose.yaml config --quiet
bash examples/firewall/smoke.sh
python3 docker/firewall/check-image.py
python3 examples/firewall/gateway_smoke.py ./netcap-firewall
helm lint charts/netcap-firewall --strict --set upstream=http://backend:8080
helm template firewall charts/netcap-firewall --kube-version 1.25.0 --set upstream=http://backend:8080
python3 charts/netcap-firewall/tests/test_render.py
# Requires kind v0.27.0, kubectl, and OpenSSL; creates/deletes its own cluster.
python3 examples/firewall/kind_smoke.py
```

`kind_smoke.py` uses a private temporary kubeconfig and a digest-pinned Kubernetes
1.32.2 node with kind v0.27.0. It tests ClusterIP traffic and policy lifecycle;
the default kind CNI does not validate production NetworkPolicy enforcement.

`Dockerfile` pins Go 1.27.0 and its multi-platform image digest, builds only
`./cmd/netcap-firewall` with `-tags coraza CGO_ENABLED=0 GOWORK=off`, and copies
the binary, CA bundle, `/LICENSE`, and `/legal` notices into `scratch`. Module
license files and actual linked versions are retained under `/legal` and checked
by `docker/firewall/check-image.py`. UID/GID 10001 runs without a shell or startup
download. The Dockerfile-specific ignore excludes local workspaces, secrets,
captures, and frontend build output while retaining Go sources and module files.

`smoke.sh` uses a unique Compose project and removes its containers and networks
on exit. It requires an unused localhost port 18080 (`FIREWALL_PORT` overrides
it). It checks an allowed request, traversal and CRS SQL injection denial, and a
chunked POST whose denial marker arrives after 32 KiB of benign body. It checks nginx logs:
exactly 1 allowed request and 0 denied requests must reach the origin. This is
stronger than observing a 403 from the client alone.

| Override | Purpose |
| --- | --- |
| `FIREWALL_IMAGE=netcap-firewall:0.1.0-local` | Default locally built image; no published release is implied |
| `SKIP_BUILD=1 FIREWALL_IMAGE=… bash examples/firewall/smoke.sh` | Test an already built image |
| `BACKEND_IMAGE=…` | Override the benign nginx 1.28.0-alpine fixture, pinned by multi-platform digest in `compose.yaml` |
| `FIREWALL_PORT=18081` | Select another localhost test port |

For an interactive deployment:

```bash
docker compose -f examples/firewall/compose.yaml up --build -d
curl --fail http://127.0.0.1:18080/
docker compose -f examples/firewall/compose.yaml logs firewall
docker compose -f examples/firewall/compose.yaml down
```

Only `127.0.0.1:18080` is published. The origin has no published port and
joins only the internal `origin` network. The firewall also joins `edge` for
client access. Do not add an origin port mapping as a troubleshooting shortcut.

## Runtime and policy contract

`examples/firewall/config.yaml` uses `version: netcap-firewall/v1` and points
at `/etc/netcap-firewall/policy.yaml`. Both files are mounted read-only.

| Setting | Default / behavior |
| --- | --- |
| `listen` / `adminListen` | `:8080` / `:9090`; separate listeners |
| `upstream` | `http://backend:8080`; one HTTP(S) origin, without credentials, query, fragment, or path prefix |
| `maxBodyBytes` / `maxResponseBytes` | 1048576 each; chart accepts 1 byte through 1 MiB, matching the bounded native policy projection; response limit applies when body inspection is enabled |
| `maxConcurrent` | 32; runtime accepts 1 through 4096 |
| `bodyTimeout` | `15s`; runtime maximum 5 minutes |
| `inspectResponse` | `false`; response-body enforcement is opt-in and bounded by `maxResponseBytes` |
| `corazaCRS` | `true` in deployment examples/chart; requires the Coraza-tagged binary; rules are embedded, with audit/debug file sinks disabled |
| `tlsCert` / `tlsKey` | Optional paired certificate/key paths for client-facing TLS termination |
| `upstreamCA` / `upstreamServerName` | Optional upstream TLS trust/name configuration; require an `https://` upstream |
| `trustedProxyCIDRs` | Empty by default; restrict forwarded-client trust to the actual ingress/LB CIDRs |

At the 1 MiB body limit, buffered bytes plus the native policy's body-string
clone require roughly 2 MiB per admitted request, or 64 MiB at concurrency 32,
before Coraza, gzip, headers, transport, and evaluator overhead. Response
inspection adds buffering and projection allocations. The chart's 256 MiB limit
is a starting point, not measured capacity; load-test before raising concurrency.

The native event ceiling is 2 MiB including body and metadata
(`internal/policy/model.go`). The previous 64 MiB configuration allowance exceeded
that projection; chart validation now caps both body settings at 1048576 bytes.
Large request uploads are unsupported. Large responses may stream only with
`inspectResponse: false`, without response-body inspection; increasing a config
value cannot turn the native evaluator into a streaming body inspector.

| HTTP coverage | Boundary |
| --- | --- |
| Request parsing | Complete bounded bodies before origin forwarding; both gzip wire and expanded bytes are bounded; JSON/XML nesting maximum 64, argument/part maximum 1000 (`internal/waf/doc.go`) |
| Response default | Status and headers checked before final headers; bodies and trailers stream without inspection |
| `inspectResponse: true` | Complete bounded response buffering; rejects upgrades and cannot serve unbounded streams |
| WebSocket / gRPC | WebSocket handshake inspection only; frames tunnel without policy inspection; client-streaming and bidirectional gRPC are unsupported |

`examples/firewall/policy.yaml` uses `version: netcap-policy/v1`, `id: baseline`,
`mode: enforce`, `default: allow`, and request-phase deny rules returning 403.
Expressions use the typed `Method`, `Host`, `Path`, `RawQuery`, `ClientIP`, `Body`,
`Headers`, `Status`, `Phase`, `Protocol`, `Modbus`, and `DNS` environment from
`internal/policy/model.go`.
Use the expr language's built-ins; arbitrary Go calls are not a policy interface.
Run `netcap-firewall validate --config …` against the exact mounted files before
rollout; Helm's JSON schema does not compile expressions or validate certificates.

## Kubernetes

The self-contained chart requires Kubernetes 1.25+ and an explicit `upstream`.
It installs a Deployment, immutable content-addressed ConfigMap, and ClusterIP
Service. There are no CRDs, RBAC objects, or mounted service-account tokens.
`mode: file` defaults to 2 replicas for declarative/GitOps policy rollout.
Image tag `0.1.0-local` names the local build; production must supply its own
published repository and patch tag or digest:

```bash
helm upgrade --install firewall charts/netcap-firewall \
  --namespace firewall --create-namespace \
  --set upstream=http://backend.application.svc.cluster.local:8080 \
  --set image.repository=registry.example.org/netcap-firewall \
  --set image.tag=0.1.0 \
  --wait --timeout 120s
```

For immutable image selection, set `image.digest=sha256:<64 lowercase hex>`;
an empty digest renders the tag path. `latest` and non-version tags fail schema
validation. The chart's version is packaging metadata, not a release assertion.

| Feature | Configuration |
| --- | --- |
| Client Service | Port 8080 by default; only the application port is exposed |
| Admin probes | Pod port 9090: `/readyz` startup/readiness and `/livez` liveness; HTTPS when `adminTLS.secretName` is set; health routes need no bearer token |
| Rootless bounds | UID/GID 10001, all capabilities dropped, read-only root, RuntimeDefault seccomp, 16 MiB memory-backed `/tmp` |
| Ingress | `ingress.enabled`, `host`, `className`, annotations, optional `tlsSecretName` |
| Direct TLS | `tls.secretName`, a Kubernetes TLS Secret with `tls.crt` and `tls.key`; client port remains 8080 |
| Origin CA | `upstreamTLS.caSecretName`, with `ca.crt`, and optional `upstreamTLS.serverName` |
| Admin credential/TLS | Existing Secret `adminTokenSecret.name` / `key` injects `NETCAP_FIREWALL_ADMIN_TOKEN` (32+ bytes); requires `adminTLS.secretName` with `tls.crt` / `tls.key` for `:9090` |
| Admin Service | `adminService.enabled` creates a separate private ClusterIP Service; requires both bearer Secret and admin TLS; never routed by the application Ingress |
| Availability | Optional `pdb.enabled`, `autoscaling.enabled`; HPA requires Metrics Server and nonzero CPU requests; managed mode rejects HPA and replicas other than 1 |

The chart and Compose allow 60 seconds for shutdown, covering the CLI's
45-second drain deadline (`cmd/firewall/main.go`). Managed `Recreate` upgrades
trade availability for exclusive state ownership; they are not zero-downtime HA.

The token-to-TLS requirement is schema-enforced in both modes. File mode permits
read-only HTTP/MCP control when both Secrets are configured; a token without
`adminTLS.secretName` fails rendering before the CLI can reject startup.

Ingress TLS normally terminates at the ingress controller. If `tls.secretName`
also enables TLS on the firewall's port 8080, configure that controller's HTTPS
backend annotation separately; the chart cannot infer a controller-specific
protocol annotation. Secret rotation may require `kubectl rollout restart`;
the content-addressed rollout covers runtime and policy ConfigMap data only.

### Network boundary

`networkPolicy.enabled` is opt-in and requires explicit `dnsPeers` and
`upstreamEgress`. Set `ingressPeers` to the actual ingress controller's namespace
and pod selectors. An empty `ingressPeers` list denies incoming application
traffic. DNS egress permits TCP/UDP 53 to the selected resolvers; upstream rules
must specify destinations and ports. Example values fragment:

```yaml
networkPolicy:
  enabled: true
  ingressPeers:
    - namespaceSelector:
        matchLabels: {kubernetes.io/metadata.name: ingress-nginx}
      podSelector:
        matchLabels: {app.kubernetes.io/component: controller}
  dnsPeers:
    - namespaceSelector:
        matchLabels: {kubernetes.io/metadata.name: kube-system}
      podSelector:
        matchLabels: {k8s-app: kube-dns}
  upstreamEgress:
    - to:
        - namespaceSelector:
            matchLabels: {kubernetes.io/metadata.name: application}
          podSelector:
            matchLabels: {app: backend}
      ports: [{protocol: TCP, port: 8080}]
```

Selectors are cluster-specific; NodeLocal DNS and CNI service-DNAT behavior may
require different peers. NetworkPolicy enforcement requires a supporting CNI.
Kubelet probe reachability must be tested on that CNI. The policy grants no
admin ingress; use a deliberate private management path if remote control is
needed. Other NetworkPolicies are additive and can widen this boundary.

The chart only selects firewall pods. Protect the origin with a separate
origin-side policy allowing the firewall's pods/namespace, remove public origin
routes, and verify a direct client-to-origin probe fails. Restricting the WAF's
egress alone does not prevent origin bypass.

## Policy control and replica state

`cmd/firewall/main.go` embeds `internal/policycontrol` into `serve` when
`NETCAP_FIREWALL_ADMIN_TOKEN` is set. It serves authenticated `/mcp` and
`/api/v1/policy/*` on the administrative listener. In file mode this API is
read-only. `netcap-firewall mcp --config …` is a separate, process-owner-authorized
stdio authoring/replay session; it cannot activate policy on the running WAF.

| Lifecycle | MCP tool |
| --- | --- |
| Discover mode, target, and limits | `get_policy_capabilities` |
| Read active/retained revision | `get_policy_revision` |
| Validate without changing state | `check_policy_bundle` |
| Retain validated candidate | `stage_policy_revision` |
| Compare / simulate | `diff_policy_revisions`, `explain_policy_decision` |
| Change target | `activate_policy_deployment` / `rollback_policy_deployment`, with `expected_revision` and `idempotency_key` |
| Inspect successful mutations | `query_policy_audit` |

Check capabilities first: file mode and managed mode have different mutation
semantics. Synthetic evaluation is not evidence of a deployed traffic decision.
After activation, verify the target's revision and send an end-to-end request.
Keep HTTP control behind a private TLS endpoint with a bearer credential; HTTP
auth also covers MCP initialization. Local stdio trusts the process owner.

### Managed singleton

`mode: managed` passes `--managed --state-dir /var/lib/netcap-firewall/managed`
to the WAF process. The chart requires `replicaCount: 1`, disables HPA through
schema validation, and sets `strategy: Recreate` to avoid overlapping SQLite
owners. It creates a retained ReadWriteOnce PVC, or uses `managed.existingClaim`.
The private 0700 state subdirectory is created by UID 10001 beneath the writable
PVC mount; `fsGroupChangePolicy: OnRootMismatch` preserves those permissions on
subsequent mounts. Existing claims must support that ownership model.

Runnable local bootstrap using the fixture backend and a short-lived test cert:

```bash
kubectl create namespace firewall
kubectl -n firewall apply -f examples/firewall/kind-backend.yaml
CERT_DIR=$(mktemp -d)
openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
  -keyout "$CERT_DIR/tls.key" -out "$CERT_DIR/tls.crt" \
  -subj '/CN=localhost' -addext 'subjectAltName=DNS:localhost'
kubectl -n firewall create secret tls firewall-admin-tls \
  --cert="$CERT_DIR/tls.crt" --key="$CERT_DIR/tls.key"
export NETCAP_FIREWALL_ADMIN_TOKEN=$(openssl rand -hex 32)
kubectl -n firewall create secret generic firewall-admin-token \
  --from-literal=token="$NETCAP_FIREWALL_ADMIN_TOKEN"
helm install firewall charts/netcap-firewall -n firewall \
  -f examples/firewall/managed-values.yaml --wait --timeout 180s
kubectl -n firewall port-forward --address=127.0.0.1 \
  svc/firewall-netcap-firewall-admin 19090:9090
# In another shell retaining CERT_DIR and NETCAP_FIREWALL_ADMIN_TOKEN:
curl --cacert "$CERT_DIR/tls.crt" \
  -H "Authorization: Bearer $NETCAP_FIREWALL_ADMIN_TOKEN" \
  https://localhost:19090/api/v1/policy/capabilities
```

The local image must already be loaded into that cluster; use a published image
override on other clusters. The certificate above trusts only localhost through
port-forward; production admin TLS needs SANs for its actual private hostname.
`examples/firewall/kind_smoke.py` performs this entire bootstrap automatically,
then stages/activates a policy, checks live Service traffic, restarts the pod,
verifies the persisted revision, and rolls policy back through the embedded API.

SQLite is authoritative after first managed bootstrap: changing the Helm policy
does not replace a persisted active revision. Back up the PVC using a consistent
SQLite/volume snapshot procedure; no backup job is installed. The PVC carries
`helm.sh/resource-policy: keep`; uninstalling the release does not remove its
state, and explicit PVC deletion is needed to discard it.

There is no fleet controller or shared global threshold. Threshold/sequence
counters and request audit buffers remain per-process and reset on restart;
managed revision and successful mutation history persist in that one SQLite
store. Multiple file-mode replicas serve independent counters and can briefly
run different policy revisions during rollout.

## Protocol gateways and optional enforcer

Gateway examples use the actual `--allow-client` CIDR flag and an existing lab
origin; there is no HTTP configuration file or administrative listener in this mode:

```bash
./netcap-firewall gateway --protocol modbus --listen 127.0.0.1:1502 \
  --upstream 127.0.0.1:502 --policy examples/firewall/modbus-policy.yaml \
  --allow-client 127.0.0.0/8
./netcap-firewall gateway --protocol dns --listen 127.0.0.1:1053 \
  --upstream 127.0.0.1:53 --policy examples/firewall/dns-policy.yaml \
  --allow-client 127.0.0.0/8
```

| Boundary | Supported parser scope |
| --- | --- |
| Modbus TCP | MBAP framing, at most 260-byte ADU; request functions 1, 2, 3, 4, 5, 6, 15, 16, 22, 23; checks response correspondence; example allows only unit 1 / FC3 / address range 0–99 |
| DNS UDP | Single-question IN classic queries, maximum 512-byte query; no EDNS, UPDATE, AXFR, DNS-over-TLS/HTTPS, or TCP fallback; names are ASCII-lowercased with a trailing dot; example permits A/AAAA for `example.test.` and descendants |
| Resource bounds | Default 64 gateway slots, 5-second IO timeout; Modbus sessions limited to 5 minutes; DNS replies bounded to 512 bytes and 3× query size by default |
| Routing | Only explicitly connected clients are inspected; default client allowlist is loopback; no transparent packet interception |

Protect Modbus writes in the request phase: a response denial cannot undo a
write already executed by the origin (`internal/gateway/modbus.go`).

`enforcer` is an optional native Linux lab tool, separate from inline WAF
decisions. The scratch image does not install `ip` or `nft`; the chart grants no
enforcer privileges. Dry-run is **false by default**, so select it explicitly:

```bash
export NETCAP_FIREWALL_ADMIN_TOKEN=$(openssl rand -hex 32)
STATE_DIR=$(mktemp -d)
./netcap-firewall enforcer --listen 127.0.0.1:9091 --dry-run \
  --namespace netcap-fw-lab --table netcap_firewall_lab \
  --interface veth-fw --destination 198.51.100.0/24 \
  --protocol tcp --hook forward --port 8080 \
  --state-file "$STATE_DIR/leases.json" --protected-cidr 192.0.2.0/24
```

Native live enforcement requires an existing named Linux network namespace and
`ip`/`nft` tooling plus appropriate privileges; it never creates the namespace
or selects the default host namespace. Keep the API loopback-only; remote access
requires a separately authenticated TLS tunnel. The bearer-protected API exposes
`GET/POST /v1/leases` and `DELETE /v1/leases/{id}`, with a maximum 15-minute TTL
and 1000 leases (`internal/enforcer`). No automatic WAF-to-enforcer feedback loop
is installed by these artifacts.

The same bearer boundary protects `/mcp`, exposing `get_enforcer_capabilities`,
`list_action_leases`, `create_action_lease`, and `revoke_action_lease`. Agents can
manage finite leases within the fixed scope; they cannot change the namespace,
interface, destination, protocol, port, or protected ranges. Listing reconciles
expired/orphaned leases and is classified as mutating. Live controllers require
the canonical shared `/run/netcap-enforcer` lock directory: separate private
`/run` mounts cannot coordinate ownership of the same namespace/table.

## Rollout and rollback

| Step | Check |
| --- | --- |
| Prepare | Build/test the pure-Go CLI; validate the mounted config/policy; select a reviewed image digest |
| Preview | `helm lint`, `helm template`, chart render tests, and Compose smoke |
| Route | Point ingress only at the WAF and deny direct origin access; verify allowed and denied requests plus origin evidence |
| Observe | Private `/metrics`, `/readyz`, `/livez`, JSON audit output; request-body and URL logging are not enabled by these artifacts |
| Update | Change `policy` or `runtime` values and run `helm upgrade --wait`; a new immutable ConfigMap name rolls pods |
| Roll back | `helm rollback firewall <revision> --namespace firewall --wait`; verify readiness and origin denial again |

A Helm rollback restores declarative image/config values, not managed SQLite
activation state or counter history. Use policy-control rollback for a managed
policy revision. Retain prior image digests and
release values. Rolling updates can briefly serve 2 policy revisions; requiring
atomic policy cutover needs a separate traffic-switch strategy. Never route
clients directly to the origin as an automatic healthcheck fallback.

## Deferred roadmap

The implemented boundary is the HTTP WAF, embedded single-target policy control,
bounded DNS/Modbus gateways, and opt-in scoped native enforcer described above.
The following work is deferred; no chart value or MCP capability here supplies it.

| Workstream | Current boundary / completion evidence still required |
| --- | --- |
| Fleet control and HA | `internal/policycontrol` owns one target and one SQLite StateDir; a future fleet controller needs authenticated target enrollment, coordinated rollout/rollback, drift reporting, and failover tests |
| Distributed state | `internal/policy` threshold/sequence counters are per-process; shared rate enforcement needs defined consistency, failure behavior, and multi-replica tests |
| Larger bodies and streaming | Deployment body limits are 1048576 bytes; larger uploads need a redesigned bounded projection and late-body no-forward tests, rather than a higher YAML limit |
| HTTP/3 and encrypted passthrough | `serve` has no QUIC/HTTP/3 listener; TLS payload inspection requires termination. Additional transports need protocol-specific integration tests |
| Broader protocol coverage | `gateway` supports only the documented classic DNS UDP and Modbus TCP subset; EDNS, DNS TCP fallback, encrypted DNS, mail, and other application protocols need dedicated parsers and fixtures |
| Transparent enforcement | Explicit proxies/gateways do not inspect arbitrary routed traffic; transparent placement and automatic WAF-to-enforcer feedback are not installed by the chart |
| Enforcer packaging | The scratch image has no `ip`/`nft`; any future privileged package needs named-namespace scope, expiry/recovery, and no-host-rule-mutation tests |
| Production operations | kind proves install/traffic/policy lifecycle, not CNI enforcement, production storage recovery, or capacity. Backup automation, restore drills, CNI checks, and throughput/latency measurements remain deployment-specific work |

## Verification pitfalls

| Symptom | Correction |
| --- | --- |
| Helm 3.8 defaults to Kubernetes 1.23 during template | Pass `--kube-version 1.25.0`; do not count a Kubernetes-version error as a negative schema test |
| Compose validates but Docker reports `invalid mount path: 'nodev'` | Quote the entire comma-containing tmpfs string in YAML flow lists |
| Container returns 403 but origin saw the request | Check origin evidence with `smoke.sh`; a response-only assertion cannot prove pre-forward enforcement |
| kind import fails on an incomplete multi-platform nginx archive | Let Kubernetes pull the digest-pinned fixture; locally load only the built firewall image |
| Managed restart reports StateDir is not 0700 | Use the private subdirectory and preserve it with `fsGroupChangePolicy: OnRootMismatch`; do not use the PVC mount root as StateDir |
