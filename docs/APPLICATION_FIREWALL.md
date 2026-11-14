# Application firewall

`netcap-firewall` is a reverse-proxy WAF for HTTP, WebSocket, gRPC and HTTP/3. The same executable also runs protocol gateways, a Linux packet firewall, a fleet controller and shared counters. The WAF needs no capture device and no host privileges. Linux enforcement is a separate, optional component.

Traffic that goes straight to the origin skips the WAF, so make the origin accept connections only from the proxy.

## Quickstart

Download the standalone `netcap-firewall` archive for Linux amd64 or arm64 from the [GitHub releases](https://github.com/dreadl0ck/netcap/releases). It is separate from the capture archives. The full `net` executable has the same commands under `net firewall`, while `netcap-firewall` takes them directly.

To build from source instead, use the build tags shown. They enable the Coraza engine and HTTP/3:

```bash
GOWORK=off CGO_ENABLED=0 go build -tags coraza,http3 -o netcap-firewall ./cmd/netcap-firewall
./netcap-firewall version
./netcap-firewall serve --help
```

Run a backend you own at `127.0.0.1:18081`. Save the two files below in the current directory. Both listeners are on loopback. The policy denies path traversal and turns on the embedded OWASP Core Rule Set (CRS), which covers SQL injection and similar attacks.

```yaml
# firewall-local.yaml
version: netcap-firewall/v1
listen: '127.0.0.1:18080'
adminListen: '127.0.0.1:19090'
upstream: http://127.0.0.1:18081
policyFile: firewall-policy.yaml
maxBodyBytes: 1048576
maxResponseBytes: 1048576
maxBufferedBytes: 16777216
maxConcurrent: 8
bodyTimeout: 15s
inspectResponse: false
corazaCRS: true
```

```yaml
# firewall-policy.yaml
version: netcap-policy/v1
id: local-example
mode: enforce
default: allow
rules:
  - id: deny-traversal
    phase: request
    expression: 'Path contains ".."'
    action: deny
    status: 403
    priority: 100
```

Validate and start the proxy:

```bash
./netcap-firewall validate --config firewall-local.yaml
./netcap-firewall serve --config firewall-local.yaml
# In another terminal:
./netcap-firewall healthcheck --url http://127.0.0.1:19090/readyz
```

Send a normal request and a request with a SQL injection in a query parameter:

```bash
curl -i http://127.0.0.1:18080/
curl -i "http://127.0.0.1:18080/?q=1%27%20OR%20%271%27=%271"
```

The first request reaches the backend. The second returns 403 and does not appear in the backend log.

To test the traversal rule, request a path that contains `..` with `curl --path-as-is`. It returns 403 too. The rule is a simple match on `..` in the request path. Keep path normalisation at the origin.

| Setting         | Result                                                                                                                                                                                                                        |
| --------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `mode: enforce` | Denied requests return the rule's status and never reach the backend.                                                                                                                                                         |
| `mode: monitor` | Native deny decisions are logged as `would-deny` and the request goes through. Coraza records CRS matches without blocking them. Malformed framing, structural validation, quotas and evaluation errors still reject traffic. |
| Switching modes | Edit the policy, validate, then restart the process.                                                                                                                                                                          |
| Recovery        | Restore the previous validated files and restart. The example changes no host packet rules.                                                                                                                                   |

To see what a policy would block on real traffic, start in `monitor` and switch to `enforce` when the `would-deny` log looks right.

`examples/firewall/smoke.sh` runs the same kind of checks against a Docker Compose stack. It also denies a marker that arrives after 32 KiB of a chunked body and checks that denied requests do not appear in the origin log.

For a deployment, decide who owns the policy before you create any persistent state:

| Mode             | Use when                                                      | Who updates and rolls back                                                          |
| ---------------- | ------------------------------------------------------------- | ----------------------------------------------------------------------------------- |
| File             | You mount a reviewed policy. This is the default for `serve`. | Files and the process or Helm rollout. Keep the previous image and files.           |
| Managed          | One target with a durable policy API                          | `--managed --state-dir …`, scoped auth and SQLite policy activation. One replica.   |
| Fleet            | Several enrolled, stable targets                              | Fleet controller generations and acknowledgments. Cannot overlap managed ownership. |
| Network / leases | A named Linux namespace, inline or for finite future blocking | `network` or `enforcer`. The rootless HTTP mode never installs host rules.          |

## Components

| Component               | What it does                                                                                                                                                               |
| ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| HTTP                    | `serve`, `validate`, `healthcheck`. Native expression policies and optional embedded Coraza 3.8.1 with CRS 4.25.0.                                                         |
| WebSocket, gRPC, HTTP/3 | `serve --websocket --grpc` and optional `--http3-listen`. Build with `-tags coraza,http3`. Each listener is opt-in.                                                        |
| Policy ownership        | File rollout, managed single-target SQLite, or an enrolled external fleet. Managed and fleet ownership cannot overlap.                                                     |
| Shared rates            | `sharedstate` with `--shared-rate-config`. A fixed-window guard. You cannot combine it with the native authority client.                                                   |
| Native rule authority   | `policy-state` with `--policy-state-config`. Thresholds, sliding and distinct windows, tuples and sequences shared across replicas, pinned to a policy revision and scope. |
| Gateways                | `gateway --protocol` supports `modbus`, `dns`, `dns-tcp`, `dns-tls`, `redis`, `postgres`, `mysql`, `smtp`, `dnp3`, `smb` and `ftp`.                                        |
| Linux                   | `network` returns NFQUEUE verdicts. `enforcer` owns finite nftables leases. Both need an existing named namespace and refuse the default namespace.                        |
| Decoder bridge          | `--firewall-policy`, `--firewall-effects-config` and `--firewall-schema` on the full capture CLI. It evaluates decoder records after the fact.                             |

## Runtime and policy contract

| Setting                            | Default and limit                                                                                                    |
| ---------------------------------- | -------------------------------------------------------------------------------------------------------------------- |
| `listen`, `adminListen`            | `:8080` and `:9090`, on separate listeners                                                                           |
| `upstream`                         | An HTTP(S) origin with no credentials, path prefix, query or fragment                                                |
| `maxBodyBytes`, `maxResponseBytes` | 67108864 each. The schema accepts 1 byte to 64 MiB. The response limit applies when you inspect response bodies.     |
| `maxBufferedBytes`                 | 67108864 in total. The schema accepts 1 byte to 1 GiB. Copies, gzip, spools, Coraza and message buffers share it.    |
| `maxConcurrent`, `bodyTimeout`     | 32 and `15s`. Limits are 1 to 4096 and at most 5 minutes.                                                            |
| `inspectResponse`, `corazaCRS`     | `false`, and `true` in the examples and the chart. CRS is embedded, and its file audit and debug sinks are disabled. |
| TLS                                | `tlsCert` and `tlsKey` together. An upstream CA or server-name override needs an HTTPS upstream.                     |
| `trustedProxyCIDRs`                | Empty. Set it to your ingress or load balancer ranges before you trust forwarded client addresses.                   |

Bodies above 64 KiB go to private temporary files. The chart uses a disk-backed `emptyDir` capped by `spool.size: 256Mi`. Compose uses a 256 MiB tmpfs that counts against the container's 256 MiB memory limit. The 64 MiB buffer budget limits how much is admitted, and not every 64 MiB request fits once all inspection copies are counted. When the budget runs out, the proxy answers 503 and frees the space when the request closes.

A policy that reads the body needs the whole body within `NativeBodyBytes`, below the 2 MiB event limit. Larger bodies are rejected, never inspected in part. JSON, XML and form values are projected up to a limit, and multipart files can spill separately. The demo Compose policy has a `Body` rule, so its effective limit is lower than the configured one. A policy that never reads the body avoids this limit.

| HTTP mode               | Coverage                                                                                                                                                                                                                                                      |
| ----------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Requests                | The full request is read and limited before forwarding. Wire and expanded gzip bytes are both limited. Nesting depth 64, arguments and parts 1000.                                                                                                            |
| Responses               | Status and headers are checked before the final headers go out. Body and trailers stream through without inspection by default.                                                                                                                               |
| `inspectResponse: true` | The whole response is buffered and limited. Streaming and upgrades are not supported.                                                                                                                                                                         |
| `--websocket`           | Each message is checked, up to 1 MiB on the wire and expanded. Optional RFC 7692 `permessage-deflate` with `server_no_context_takeover` and `client_no_context_takeover`. Messages are forwarded uncompressed.                                                |
| `--grpc`                | HTTP/2 message checks with identity or gzip encoding. A rejected message does not release its frame headers.                                                                                                                                                  |
| `--http3-listen`        | QUIC/TLS termination with the runtime certificate and key, and no 0-RTT. With `--grpc` it accepts gRPC message envelopes over HTTP/3 and bridges them to an HTTP/2 origin, including duplex bodies and gated trailers. This is not standard gRPC over HTTP/3. |

Policies use `netcap-policy/v1` with typed HTTP, `Network`, `TLS`, `DNS`, `Modbus` and protocol-adapter fields. Run `netcap-firewall validate` on the exact files you mount. Helm does not compile expressions.

## Kubernetes

`charts/netcap-firewall` needs Kubernetes 1.25 or later and an `upstream` value. The default install is a two-replica file-mode Deployment, an immutable ConfigMap named by its content hash and a ClusterIP Service. It creates no CRDs, RBAC grants or service account tokens. A `0.1.0-local` chart version is a local build.

```bash
helm upgrade --install firewall charts/netcap-firewall -n firewall --create-namespace \
  --set upstream=http://backend.application.svc.cluster.local:8080 \
  --set image.repository=registry.example.org/netcap-firewall \
  --set image.digest=sha256:<reviewed-64-hex-digest> --wait --timeout 180s
```

| Feature                | Values                                                                                                                                                                                                            |
| ---------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Security context       | UID/GID 10001, all capabilities dropped, read-only root, RuntimeDefault seccomp. A writable, disk-backed `/tmp` of 256Mi by default.                                                                              |
| Messages               | `websocket: true` and `grpc: true` pass the CLI flags. Both default to false.                                                                                                                                     |
| HTTP/3                 | `http3.enabled: true` and optional `http3.port` (8443). Needs `tls.secretName`. Adds a UDP container port, Service port and NetworkPolicy ingress next to TCP.                                                    |
| Ingress and direct TLS | `ingress.*` and `tls.secretName`. When the WAF terminates TLS, set your ingress controller's HTTPS-backend annotation separately.                                                                                 |
| Admin                  | A bearer secret `adminTokenSecret.name/key` needs `adminTLS.secretName`. Optional `adminService.enabled`. Never expose it on the application Ingress.                                                             |
| Probes                 | `/readyz` and `/livez` on admin port 9090, over HTTPS when admin TLS is on. Health routes need no bearer.                                                                                                         |
| Origin TLS             | `upstreamTLS.caSecretName` (`ca.crt`) and optional `serverName`. Needs an HTTPS upstream.                                                                                                                         |
| Shared guard           | `sharedRate.configSecretName` (`config.json`, optional CA and client cert files) with `credentialsSecretName` (`tokenEnv` entries). Set both.                                                                     |
| Native rule authority  | `policyState.configSecretName` (`config.json`, CA and client TLS files) with `credentialsSecretName`. Mounts `/etc/policy-state` read-only and passes `--policy-state-config`. Cannot be mixed with `sharedRate`. |
| Fleet targets          | `mode: fleet` uses a fixed-size StatefulSet, a headless Service and a cache PVC per pod. Needs `fleet.configSecretName` and `credentialsSecretName`.                                                              |
| Availability           | File mode allows HPA and PDB. Managed mode is one replica with Recreate. Fleet mode does not allow HPA, because targets are enrolled explicitly.                                                                  |

The chart never writes token values into Secrets. After you change a Secret, restart the pods. The ConfigMap hash only covers runtime and policy data. For fleet `targets`, mount `targets-netcap-firewall-0.json`, `…-1.json` and so on from the config Secret. Kubernetes expands `$(POD_NAME)` in the CLI argument. Each JSON file declares its own enrolled `targetID`, `tokenEnv`, scope, controller URL and cache directory `/var/lib/netcap-firewall/agent`. `ca.crt` can live in the same Secret. Replicas share the application's target-token Secret and never operator credentials. Random Deployment pod names are not enrollment identities.

### Routes

Each route uses one origin, one transport and one policy. A route reload rebuilds all enabled adapters together.

| Setting                 | Behaviour                                                                                                                                                                                                                                                                                                                                                 |
| ----------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| API validation          | Each route declares `descriptorPath`, `descriptorSHA256` and optionally `apiValidateResponse`. Only the listener's `bootstrapDir` is shared. There is no global or neighbour fallback. WebSocket needs explicit API passthrough.                                                                                                                          |
| Managed console and MCP | `--route-id=<bootstrap ID>` selects one route target. The policy bundle ID is checked on stage, activation and recovery. Helm uses `routeID`. A global activation cannot update tenant routes.                                                                                                                                                            |
| TLS reload              | `SIGHUP` stages the listener and client identity for all bindings, then reloads local route policies atomically. Requests in flight keep their policy and API snapshot. Existing TLS connections keep their handshake identity.                                                                                                                           |
| CRS exclusions          | `crsProfile.exclusions` matches an exact `path` and `method`, with an owner, a reason and an expiry. `parameter` uses Coraza ARGS names, for example `json.text`. `crsTargetExclusions` goes into the same registry, with `argument` mapped to `parameter`, and has no expiry. API, native and structural checks stay active.                             |
| Routed CLI adapters     | `--route-id=<bootstrap ID>` binds fleet, shared-rate, native state and effects to one route. Only that route admits effect rules, and only when a broker exists. Readiness includes the route's dependencies. A cold, drained, revoked or unavailable route rejects its own traffic without draining its neighbours.                                      |
| Helm API artifacts      | `apiArtifactsConfigMap` mounts reviewed descriptors read-only at `/etc/api-bootstrap`. `apiContract`, or each route's `apiContract`, gives a relative `descriptorPath`, a 64-hex `descriptorSHA256` and optionally `apiValidateResponse`. Create the ConfigMap before you install. Missing mounts, path traversal and unpinned declarations are rejected. |

### Network boundary

`networkPolicy.enabled` needs `dnsPeers`, `upstreamEgress` and `ingressPeers`. With no ingress peers, application traffic is denied. DNS allows TCP and UDP 53. Add the control services to egress if you use fleet or shared rates. The chart selects WAF pods only, so add a separate policy on the origin side that allows only the WAF. Policies add up, and the cluster needs a CNI that enforces them.

## Policy control and replica state

`serve --auth-config /etc/firewall/auth.json` serves authenticated `/mcp` and `/api/v1/policy/*` on the admin listener. File and fleet policies stay read-only. `mcp --config … --auth-config …` starts an isolated, read-only stdio session with `stdio` grants. It does not connect to a running WAF.

| Single-target lifecycle     | MCP tool                                                                                                           |
| --------------------------- | ------------------------------------------------------------------------------------------------------------------ |
| Capabilities and revision   | `get_policy_capabilities`, `get_policy_revision`                                                                   |
| Validate and stage          | `check_policy_bundle`, `stage_policy_revision`                                                                     |
| Compare and simulate        | `diff_policy_revisions`, `explain_policy_decision`                                                                 |
| Activate and roll back      | `activate_policy_deployment`, `rollback_policy_deployment`. They need an expected revision and an idempotency key. |
| Successful mutation history | `query_policy_audit`                                                                                               |

### Identity and authorization

A grant covers `tenant`, `app`, `environment`, `target` and an operation, and it works the same way over REST and MCP. An empty field matches only an empty field. Write `*` to match anything. Policy and enforcer scope is bound at bootstrap. Fleet admin requests name the tenant and app. A job transition must be authorised for every target stored on the job. A workload's `desired` and `ack` calls need a principal ID equal to the enrolled target ID and a `lease` grant. Shared and native state take their single tenant and app binding from the grants.

| Action               | Operations                                                                                                     |
| -------------------- | -------------------------------------------------------------------------------------------------------------- |
| `read`               | Capabilities, revisions, diff, status, lease listing, state health                                             |
| `author`             | Check and stage bundles                                                                                        |
| `evaluate`           | Replay of test inputs, and shared counters and native state evaluation                                         |
| `deploy`             | Activate, promote and roll out. Drain, revoke and resume targets.                                              |
| `rollback`           | Roll back. Process-owned fleet maintenance uses a bootstrap supervisor.                                        |
| `lease`              | Create and revoke leases. Enrolled target `desired` and `ack`.                                                 |
| `audit`              | Mutation audit queries and `audit_export`                                                                      |
| `prune`              | `retention_preview`, `prune`, `audit_ack`. A read-only audit grant cannot delete records.                      |
| `metrics`            | `/metrics`, fleet REST `metrics` and MCP `fleet_metrics`. Aggregate fleet metrics need environment-wide scope. |
| `approve`            | Issue receipts. Also needs the grant for the approved action.                                                  |
| `manage-credentials` | Revoke fingerprints. Needs an authority-wide grant with an empty scope.                                        |

Example `--auth-config` file. Service bootstrap files point to the same file with `authConfig`. Secrets are environment variable names, never values:

```json
{
  "stateDir": "/var/lib/firewall/identity",
  "scope": {"tenant":"lab","app":"web","environment":"test","target":"edge"},
  "origin": "https://console.example",
  "static": [{"tokenEnv":"FIREWALL_READER_TOKEN","principal":{
    "id":"reader","grants":[{"scope":{"tenant":"lab","app":"web","environment":"test","target":"edge"},"actions":["read"]}]
  }}]
}
```

| Bootstrap field                       | Meaning                                                                                                                                                                                                |
| ------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `providers`                           | You pin the `issuer`, `audience` and `jwksURL`. `subjects` maps each subject to a local principal and its grants. Token claims cannot assign roles or choose key URLs.                                 |
| Provider time limits                  | Integer nanoseconds. `ttl` defaults to 60s (1 to 300s), `maxLifetime` to 900s (1 to 3600s) and `clockSkew` to 0 (0 to 60s). A JWT needs `exp`, `iat`, a bound subject, issuer and audience.            |
| JWKS                                  | RS256, ES256 or EdDSA public signing keys with a non-empty `kid`. HTTPS, or loopback HTTP, and no redirects. At most 32 keys and 256 KiB. One refresh per second per provider, and no per-`kid` cache. |
| `stateDir`                            | A private 0700 directory with a 0600 `identity.sqlite`. Holds revoked fingerprints and one-use approvals. Back it up with the policy state.                                                            |
| `databaseURLEnv`, `databaseNamespace` | A shared PostgreSQL identity ledger. Cannot be combined with `stateDir`. Use one dedicated schema for every owner and keep it with the service state.                                                  |
| `approvalKeyEnv`, `protected`         | A base64 64-byte Ed25519 private key, and the action and scope rules for `deploy`, `rollback` and `lease`. Both need durable identity state.                                                           |
| `stdio`                               | The local principal. With no grants it has no privileges.                                                                                                                                              |
| `origin`                              | The exact first-party HTTP(S) origin, without wildcard, path, credentials or CORS headers. Optional.                                                                                                   |

To revoke a token for good, send `POST /api/v1/auth/revoke {"fingerprint":"<SHA-256 hex of bearer>"}` or use the MCP tool `revoke_firewall_credential`. The revocation survives a restart. Without an identity ledger these calls fail. To rotate static tokens, issuer trust, subject grants or `revokedIDs`, change the config and restart. Removed JWKS keys stop working after the cache expires, which takes at most 300s. Bearers are accepted only in the Authorization header, never in a URL.

A protected policy or fleet write carries a `receipt`. Get one from `POST /api/v1/policy/approval`, `POST /api/v1/fleet/approval`, or the MCP tools `issue_policy_approval` and `fleet_approval`. The `approval` object contains `actor`, `action`, `scope` and `digest`. Bind the whole request, including CAS values, revisions, targets and idempotency key, with `ApprovalDigest(operation, Request)`. The fleet approval scope is the enclosing tenant, app and environment, and the stored job targets decide whether protection applies. The enforcer uses `POST /v1/approval` or the MCP tool `issue_lease_approval`, with `ActionApprovalDigest` or `DeleteApprovalDigest`. Pass a `receipt` create argument or the `X-Firewall-Approval` header (DELETE uses the header). The signing principal must differ from `actor`. A receipt expires after 300s and works once, and a failed operation can still consume it. Operations outside the `protected` rules need no receipt.

With the PostgreSQL ledger, every process shares revocation reads and writes and one-use approval consumption. PostgreSQL service owners need it. The bootstrap fingerprint pins the normalised grants, the provider policy, the approval public key and the protection rules. JWKS caches and private signing keys stay in each process. A change to shared policy needs a coordinated bootstrap migration, and a reload refuses it.

The embedded `/console/` needs the configured first-party origin for browser API requests in identity mode. Bearers stay in browser memory. Token-based admin without an identity config needs `--legacy-admin` on `serve` and `enforcer`. In Helm that means `legacyAdmin: true` plus `adminTokenSecret` (for the enforcer, `tokenSecret`). Token settings (`tokenEnv`, `identities`, `principals`) cannot be mixed with `authConfig` identities.

| Packaging         | Details                                                                                                                                                                                                                                                                                                                                                                                                 |
| ----------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Role bootstrap    | `examples/firewall/managed-values.yaml` selects `authConfigSecret` and individual `tokenEnvironment` Secret keys. `examples/firewall/auth.json` gives a reader `read,metrics` and an operator `read,author,evaluate,deploy,rollback`, only for `example/web/lab/edge`. Replace the example scope and origin before use. No default admin bearer is generated.                                           |
| All three charts  | `authConfigSecret: {name: firewall-auth, key: auth.json}` mounts `/etc/firewall-auth/auth.json` read-only. The WAF passes `--auth-config`. The enforcer entrypoint uses `ENFORCER_AUTH_CONFIG`. The fleet controller's `config.json` must contain `"authConfig":"/etc/firewall-auth/auth.json"`. `sharedstate` and `policy-state` have their own scoped principal bootstrap, not the fleet auth fields. |
| Console origin    | Set JSON `origin` to the exact scheme, host and port that users open, with no path. A browser `Origin` must also match the listener's scheme and HTTP Host. Forwarded headers cannot change this. CLI bearer requests can omit `Origin`.                                                                                                                                                                |
| Durable approvals | Put the auth `stateDir` on a writable persistent mount: `/var/lib/netcap-firewall/identity`, `/var/lib/control/identity` or `/var/lib/netcap-enforcer/identity`. PostgreSQL uses `databaseURLEnv` and `databaseNamespace` instead, and mixing both is a CLI error. `approvalKeyEnv` is a Secret-backed Ed25519 private key.                                                                             |

Pitfalls:

* A shared-identity lease or status read never reconciles or deploys. The process-owned maintenance loops do that.
* Fleet authority enrollment omits `tokenEnv` and matches the enrolled ID.
* Retained SQLite state pins the identity mode and resource binding. If you change the tenant, environment or target, or switch to token mode, you need newly provisioned state. Rotating credentials does not change the pin.

`appliance plan --manifest ...` supports `mode: production` with a `targetID`. In production, `apply`, `recover`, `remove` and `status` also need `--auth-config`, `--operator-token-env` and `--reviewed-plan-digest` equal to the plan's `digest`. The bootstrap scope's target must equal `targetID` and grant `deploy` over all four scope fields. The named-namespace, private-prefix, ownership and recovery checks still apply. If protection is configured, add `--approval-receipt-env` with a one-use receipt that binds `appliance.ApprovalDigest(planDigest, operation)`. `mode: lab` needs `NETCAP_APPLIANCE_LAB=1` and Docker.

### Managed singleton

`mode: managed` passes `--managed --state-dir /var/lib/netcap-firewall/managed`, needs one replica, disables HPA and sets Recreate. Storage is a retained ReadWriteOnce PVC or `managed.existingClaim`. UID 10001 creates a private 0700 subdirectory, kept by `fsGroupChangePolicy: OnRootMismatch`. The first start imports the file policy. Later Helm changes do not replace the SQLite activation.

### Fleet and shared services

`charts/netcap-firewall-control` is off by default. Install one release per service with `enabled=true`, `service=fleet-controller|sharedstate|policy-state`, and the existing `configSecretName`, `credentialsSecretName` and `tlsSecretName`. Both backends use rootless TLS on ClusterIP port 9092. The TCP readiness probe only shows that the socket is open. The authoritative API and guard probes also check the database.

| `persistence.backend` | Control chart                                                                                                                              |
| --------------------- | ------------------------------------------------------------------------------------------------------------------------------------------ |
| `sqlite` (default)    | `replicaCount: 1` only, Recreate, retained PVC, bootstrap `stateDir: /var/lib/control/state`                                               |
| `postgres`            | `replicaCount >= 2`, RollingUpdate, no local state mount or PVC. Needs an external database URL variable and a dedicated schema namespace. |

Set `persistence.postgres.databaseURLEnv` and `databaseNamespace` to match the JSON fields of the bootstrap Secret. `credentialsSecretName` supplies the URL variable. **Never put a database URL or password in Helm values.** PostgreSQL bootstrap has no `stateDir`, and the CLI rejects mixed SQLite and Postgres settings and a literal `databaseURL`. All replicas of one service share a namespace and identical bootstrap identities. Fleet and counters use different namespaces. A non-loopback database URL needs `sslmode=verify-full`, and the CA goes next to the bootstrap JSON. The chart cannot read a Secret while rendering offline, so it only declares the expected variable and namespace.

```bash
helm upgrade --install fleet charts/netcap-firewall-control -n firewall \
  --set enabled=true --set service=fleet-controller --set persistence.backend=postgres \
  --set replicaCount=2 --set configSecretName=fleet-bootstrap \
  --set credentialsSecretName=fleet-credentials --set tlsSecretName=fleet-tls \
  --set persistence.postgres.databaseURLEnv=CONTROL_DATABASE_URL \
  --set persistence.postgres.databaseNamespace=ncf_fleet --wait
```

The controller bootstrap lists `identities` and `targets`. The shared-state bootstrap lists `principals`. Durations in agent and rate JSON are integer nanoseconds, not strings. A shared guard example:

```json
{"url":"https://sc-control:9092","tokenEnv":"STATE_TOKEN","ca":"/etc/shared-rate/ca.crt","window":3600000000000,"limit":3,"group_by":"Path","id":"app-rate","unit":"request"}
```

The fleet status URL for a release named `fc` in the example is `https://fc-control:9092/api/v1/fleet/status?tenant=lab&app=example`. Other reads are GET `audit` and `capabilities` under `/api/v1/fleet/`. Writes are POST `stage`, `rollout`, `activate`, `promote`, `rollback`, `drain`, `revoke` and `resume`. Targets use GET `desired` and POST `ack`, and their identity comes from the bearer, never a query parameter. A scoped identity can omit its bound scope. A rollout compares and swaps the generation of each target and waits for acknowledgments, so it is not an atomic switch across the fleet. Native thresholds and sequences are local by default. `--policy-state-config` evaluates them at the authority instead. The shared-rate guard is a separate fixed-window feature.

### Distributed native rule state

The files `policy-state-bootstrap.json`, `policy-state-client.json`, `policy-state-values.yaml` and `policy-state-waf-values.yaml` under `examples/firewall/` show the exact JSON and Secret references. Install the control example as release `native`, so that the client URL `https://native-control:9092` matches its Service.

The bootstrap accepts `principals`, `allowEffects`, `maxRevisions`, `maxStateBytes` and either a private `stateDir` or `databaseURLEnv` with `databaseNamespace`. It does not accept `identities`, `targets` or the shared-rate `maxKeys`. The authority's credentials hold the database URL and the principal tokens. A caller's credentials hold only its `tokenEnv`. SQLite uses one fenced WAL owner. PostgreSQL replicas share one dedicated namespace and identical principals, limits and effect-admission settings.

Client JSON takes `url`, `tokenEnv`, `ca`, optional `cert` and `key`, and `requestTimeout` in integer nanoseconds (default 5s, maximum 10s). Time windows use the authority's clock, which is the PostgreSQL database clock with a stored monotonic watermark. Callers cannot supply a clock. A new revision starts with its own state rather than a global reset. If you roll back to a retained revision, its live windows can resume. A restart does not reset committed state.

Health is the authenticated GET `/api/v1/policy-state/health`, not the fleet `/health` route. `healthProbe.enabled` adds a rootless curl sidecar. `authorizationSecretName` holds a full `Authorization: Bearer …` line under the key `authorization`, and `caSecretName` holds `ca.crt`. The probe verifies TLS against the Service name (or `serverName`), connects to the pod's loopback and expects HTTP 200. The example uses a separate health principal. Without the option, the control chart only probes the socket. WAF readiness uses the authenticated authority probe whenever the native client is configured.

Every HTTP or gateway event, WebSocket or gRPC message and network packet costs a remote evaluation and a database transaction. A timeout, overload, an unavailable or unclear commit, or loss of the authority fails closed. There is no local fallback and no automatic retry. Network mode also needs `failure-verdict=deny`, no bypass when the listener is missing and no fail-open on queue overflow. Size the RPC timeout and the queue deadline for your latency. Both the WAF and the network enforcer chart take the Secret-reference client settings.

The authority receives the projected events, including HTTP bodies and headers up to the projection limits, in plaintext inside the trusted process after TLS termination. The SQL store keeps scoped policy artifacts, state digests and timing data, not raw bodies or datagrams. Group hashes do not make the data anonymous. Effect policies need both `allowEffects` on the authority and broker admission on the caller. The capture audit bridge evaluates records after the fact, and these flags do not connect its observer to the authority.

### Backup and restore

| Store                     | Procedure                                                                                                                                                                                                                         |
| ------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| SQLite control services   | Stop the old owner and make sure it cannot start again. Run `netcap-firewall backup --service fleet\|sharedstate\|policy-state --config … --output /absolute/private/snapshot.sqlite`. Restore into a new, empty state directory. |
| Postgres control services | Use the scheduled backup below or your own schema dump. Roles, WAL, point-in-time recovery and restore belong to your database operator. The SQLite backup command rejects Postgres.                                              |
| Managed policy control    | `managed_snapshot.py` with `backup` or `restore`, `--state-dir /absolute/state --snapshot /absolute/private/snapshot.sqlite`. It holds the same ownership lock for the whole run.                                                 |

Snapshots contain revisions, audit data and counters. Keep them in private directories with 0600 files. A restore needs an empty destination and does not stop another host from running. SQLite has one authoritative owner. Postgres allows active-active application replicas against one writable primary. **Primary election, fencing, replication durability and database failover are up to your database operator.**

### Scheduled Postgres backups

The control chart adds no backup resources by default. Set `backup.enabled` only with Postgres, Kubernetes 1.27 or later, a unique cluster-wide `backup.scope` and Secrets that already exist. `examples/firewall/backup-values.yaml` shows the values. It has no repository URL or credentials.

| Setting                       | Details                                                                                                                                                                                                                                |
| ----------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `backup.databaseSecretName`   | A `pg_service.conf` with a service `[backup]` (host, port, dbname, user, password and `sslrootcert=/db/ca.crt`), and `ca.crt` in the same Secret. `pg_dump` forces `sslmode=verify-full`. No password or DSN appears in the arguments. |
| `backup.repositorySecretName` | `RESTIC_REPOSITORY` and the backend credentials as environment entries. Optional config and CA files mount read-only at `/repository`, and `ca.crt` is used automatically. Keep credentials out of the repository URI.                 |
| `backup.passwordSecretName`   | A separate Restic password file, key `password` unless `passwordSecretKey` says otherwise. The repository must already be initialised.                                                                                                 |
| Dump                          | Digest-pinned Postgres 17.11 `pg_dump` of the configured schema in a consistent custom format. 64 MiB default file limit, 5s lock wait, private 0600 files. A failed or oversize dump is never uploaded.                               |
| Encryption                    | A separate digest-pinned Restic 0.18.1 image. It does not install software, initialise the repository, change the Kubernetes API or pause the application.                                                                             |
| Retention                     | Daily 7, weekly 4, monthly 3. `forget` always selects both the host and the tag. `prune: false` by default. With prune on, unreferenced blobs are removed repository-wide after the scoped forget.                                     |
| Job limits                    | No overlap, a 900s deadline, one retry and a 3600s TTL for finished Jobs. Rootless 10001, capabilities dropped, read-only root, no service account token, limited work and cache volumes.                                              |

A backup covers every tenant in the service schema. It is not a per-tenant export. You provide the repository, its access policy, key rotation and an alert for failed backups. While prune is off, retention does not limit the repository's size on disk. The plaintext dump lives only in the private temporary volume and is removed after the upload. The chart does not stop or scale a SQLite service for you.

```bash
helm upgrade --install fleet charts/netcap-firewall-control -n firewall -f examples/firewall/backup-values.yaml
```

## Protocol gateways and optional enforcer

`redirect` sends new sessions for a routed service to a TCP message gateway that is already running. Start the gateway inside its named namespace, then install the redirect from outside it:

```bash
ip netns exec firewall-router netcap-firewall gateway --protocol redis \
  --listen 10.90.0.1:16379 --upstream 10.91.0.2:6379 \
  --allow-client 10.90.0.0/24 --policy /etc/netcap-firewall/redis.yaml
# Separate process; SIGTERM removes only this redirect's own table.
netcap-firewall redirect --namespace firewall-router --interface g0 \
  --service-cidr 10.91.0.2/32 --service-port 6379 --gateway-port 16379 \
  --protocol redis --tls-mode plaintext
```

Start the gateway before you install the redirect. `--tls-mode terminated` records that you terminate TLS. The gateway still needs its TLS certificates and termination settings. Opaque TLS is rejected. A redirect applies to new conntrack sessions and one fixed upstream.

Gateway defaults are 64 connections, 1 MiB messages, 5-second I/O, 5-minute sessions and `--max-state-entries=128`. Run `gateway --help` for the client and upstream TLS flags. Deny Modbus writes in the request phase, because denying the response cannot undo a write.

| Example in `examples/firewall/`              | Contents                                                                                                                                                                                                                             |
| -------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `network-policy.yaml`                        | Default-deny packet policy with `Protocol == "network"`, service selectors for both directions, a rule that denies a visible SNI, and an allow for unclassified TCP/443                                                              |
| `advanced-policy.yaml`                       | Sliding counts, distinct paths and ports, grouping tuples and a named login-to-export sequence. Local by default, or per scope and revision with `--policy-state-config`.                                                            |
| `effects-policy.yaml`, `effects-config.json` | An HTTP path or SMTP RCPT denial that emits a `block_source` intent. The operator config fixes the HTTPS endpoint, the `LAB_ENFORCER_TOKEN` variable, the CA and the future TCP/8080 scope. A policy cannot supply its own endpoint. |
| `audit-smb-policy.yaml`                      | `Protocol == "audit"`, `RecordType == "SMB"`, `Fields["ShareName"] == "ADMIN$"`. Only a live capture admitted by the effects config can request a future lease.                                                                      |

For packet mode, add `--inspect-tls`. `TLS.Encrypted` is true when a ClientHello is visible. False means unknown: a SYN, an incomplete hello or missing metadata. It does not mean plaintext. The example allows the unknown case so handshakes can finish. ECH can hide the real SNI. No rule decrypts payloads. `effects-config.json` expects `lab-enforcer.crt` in the working directory and a TLS enforcer at `127.0.0.1:19091`. Its `retention` is in nanoseconds. The fixed lease destination is `198.51.100.0/24` on interface `lab0`, forward, TCP/8080, protecting `192.0.2.0/24`. The SMTP rule asks for that same future scope, not a global or SMTP-wide ban. See [Firewall response actions](FIREWALL_RESPONSE_ACTIONS.md) for a worked example.

| Gateway               | What it supports                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| --------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| MySQL                 | Protocol 4.1 auth relay with separately negotiated TLS on each leg. QUERY, INIT\_DB, PING and a prepared-statement lifecycle with limits. Query metadata gates execution. Rejects multipart 0xffffff packets, compression, LOCAL INFILE, multi-results, long data, cursors and unsupported capabilities.                                                                                                                                                                                                                                                                                                                                                                                                       |
| DNP3                  | CRC-checked link frames, confirmed and unconfirmed transport, and sequence-bounded reassembly. Object profiles for READ, WRITE, SELECT, OPERATE and restart functions. One request APDU per authorisation. Rejects unsolicited messages and unknown profiles.                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| SMB2/3 plaintext      | Direct TCP with a request length limit. Headers and compound requests are checked. The whole request compound is authorised before forwarding. Rules can use `smb.command`, the raw UTF-16 `smb.path` and `smb.share`, session- and tree-scoped file handles, CREATE access, disposition and options, and READ/WRITE length and offset. WRITE content and successful READ responses are gated. Authentication stays opaque. Signed bytes are forwarded unchanged and not verified. A denial closes the connection without a forged reply. Rejects SMB1, encrypted or compressed transforms, async, IOCTL, SET\_INFO, locks, leases and create contexts. Tested against an emulated disk, not Samba or Windows. |
| FTP                   | CRLF commands and RFC 959 multiline replies. The EPSV data listener binds to the control listener's address. The data client must match the control client, and the origin data target is pinned to the control peer on ports 1024 to 65535. STOR is fully buffered and checked before the origin sees the command or data connection. RETR, LIST and NLST are fully buffered before release. Rejects implicit TLS, active PORT and EPRT, PASV, AUTH, PBSZ and PROT upgrades, APPE, MODE, STRU, SITE and unknown commands. `ftp.path` and `ftp.argument` are raw and not canonical file system paths.                                                                                                          |
| Redis, Postgres, SMTP | Redis rejects RESP3, HELLO, transactions and pub/sub. Postgres rejects COPY. SMTP rejects STARTTLS, BDAT and BURL, and supports implicit TLS. None of these modes turn into opaque passthrough.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |

FTP transfers are limited to `--max-message-bytes`.

### Decoder audit bridge

Run `capture --firewall-schema` with the full `net` capture binary to list the registry of all 220 compiled protobuf message types, with field sensitivity and projection limits. `capture --read traffic.pcap --firewall-policy examples/firewall/capture-policy.yaml` evaluates existing decoder records after the fact, and a replay never contacts an enforcer. A live `--iface` capture also needs `--firewall-effects-config` before it can request source-attributed future blocks. Service and upload mode do not support it. Record rules bind through `RecordType`, typed `Fields` and `audit.schema_version`. A deny here is an observation, not a dropped packet. Projection limits are 128 fields, 1024 bytes per value, four collection entries, depth six and 4096 traversal nodes.

`enforcer` serves bearer-protected `/v1/leases` and `/mcp`, with at most 1000 leases and a 15-minute TTL. Its CLI default is live, so add `--dry-run` to preview. A shared `/run/netcap-enforcer` lock coordinates namespace and table ownership. Inode checks on the named namespace reject aliases of the current or default namespace.

### Enforcer package

The enforcer image is built from `docker/enforcer/Dockerfile`. `--help` does nothing by default, and you must set the live scope yourself.

| `charts/netcap-enforcer` | Details                                                                                                                                                                                          |
| ------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Enablement               | Off by default. Needs a dedicated lab `nodeSelector` and an existing named namespace and interface.                                                                                              |
| Privileges               | Drops all capabilities and adds only NET\_ADMIN and SYS\_ADMIN. Not privileged. Read-only root. Seccomp and AppArmor are Unconfined so that setns, unshare and mount work.                       |
| Host visibility          | Host networking lets the default-namespace check cover the node's network. A private PID namespace blocks access to host PID 1.                                                                  |
| Mounts                   | `/run/netns` read-only with HostToContainer, a shared private `/run/netcap-enforcer`, and a node-local state directory. It creates no host namespace or route.                                   |
| `mode: leases`           | Existing bearer Secret, destination, protocol and port. The API listens on loopback only. No Service or Ingress.                                                                                 |
| `mode: network`          | `scope.protectedCIDRs` selects the protected traffic, with optional management exemptions. An immutable policy ConfigMap. Queue, deadline, failure and TLS-metadata values map to the CLI flags. |
| Native network authority | `policyState` Secret references pass the client config. With it on, the renderer and the CLI reject fail-open queue and deadline settings.                                                       |
| Network failure policy   | Queue 100, length 1024, deadline 100ms, failure verdict deny. No bypass without a listener and no fail-open on overflow.                                                                         |
| Updates                  | `OnDelete` means you replace the pod yourself. The network table is fixed by the runtime. The lease table has its own scope.                                                                     |

## Rollout and rollback

| Step             | Check                                                                                                                                      |
| ---------------- | ------------------------------------------------------------------------------------------------------------------------------------------ |
| Prepare          | Build with the release tags, validate the exact config and policy, and review the image digest and the Secret bootstrap identities.        |
| Preview          | Render the Helm chart and run `examples/firewall/smoke.sh` against a Compose stack.                                                        |
| Route            | Send ingress only to the WAF. Add a separate origin policy. Test allowed and denied traffic and look at the origin log.                    |
| Observe          | Use the private readiness and metrics endpoints and the redacted audit log. Shared guard and fleet readiness are dependencies.             |
| File rollback    | `helm rollback firewall <revision> -n firewall --wait`, then re-test traffic. Pods that are rolling can briefly serve different revisions. |
| Managed rollback | Use the single-target policy API to restore the SQLite activation. A Helm rollback does not restore managed state.                         |
| Fleet rollback   | Roll back through the controller with the expected job phase and generations. Check the acknowledgments and live target traffic.           |

No mode sends clients straight to the origin when the WAF fails. Keep the previous image digests, values and consistent state snapshots.

To plan an upgrade from signed offline bundles, run `plan-upgrade`. It checks both manifests and writes a 0600 state archive. It rejects unsupported config or policy schema versions, files outside the backup tree, symlinks, existing output files and implicit downgrades. It runs only fixed verification tools, never deployment commands, and never changes live state. Validate the configuration and run a Helm diff yourself.

```bash
# Stop writers first. Include configuration, policy and consistent state.
python3 scripts/firewall_release.py plan-upgrade \
  --current ./current --candidate ./candidate --offline --trust-root /trusted/sigstore-root.json \
  --state /private/firewall-state --config /private/firewall-state/config.yaml \
  --policy /private/firewall-state/policy.yaml --backup /private/backups/pre-upgrade.tar.gz \
  --output /private/backups/upgrade-plan.json --quiesced
```

To roll back, use the previous signed bundle as `--candidate` and add `--allow-downgrade`. To verify a bundle offline, run `python3 scripts/firewall_release.py verify ./candidate --offline --trust-root /trusted/sigstore-root.json` with a Sigstore trusted root you obtained separately.

## Limits

| Limit                 | Detail                                                                                                                                                                                                                             |
| --------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Single database owner | SQLite is one owner. Postgres replicas are active-active, but primary fencing and database failover are yours. Restoring a stale snapshot loses data.                                                                              |
| Fleet rollouts        | Not atomic. Acknowledgments are collected per target.                                                                                                                                                                              |
| Protocol coverage     | No decryption of passthrough payloads, no WebSocket context takeover or window-size negotiation, no HTTP/3 origin message transport, no FTP active or PASV modes. SMB and the other gateways cover only the profiles listed above. |
| Capacity              | The 64 MiB values are limits, not throughput figures. Size each deployment yourself and test other CNIs, storage providers and UDP ingress, load balancer or NAT paths.                                                            |

## Troubleshooting

| Symptom                                        | Fix                                                                                                                |
| ---------------------------------------------- | ------------------------------------------------------------------------------------------------------------------ |
| Client gets 403 but the origin saw the request | The request was not stopped at the WAF. Check the origin log, as `smoke.sh` does.                                  |
| Default-deny routed policy breaks allowed TCP  | Allow the replies from the protected service too. NFQUEUE sees both directions, not just client destination ports. |
| Managed state directory is not 0700            | Use a private subdirectory below the PVC mount and keep ownership across mounts.                                   |
| `rollout status` rejects OnDelete              | Delete the chosen pod, wait for the new one and check the API and the table.                                       |
| Helm 3.8 renders for Kubernetes 1.23           | Pass `--kube-version 1.25.0` or newer.                                                                             |
| Compose says `invalid mount path: nodev`       | Quote the whole tmpfs string when it contains commas in a flow list.                                               |

See also the [licence page](license.md) and the [third-party components](license.md#third-party-components-and-data).
