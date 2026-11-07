package firewallfleet

// Integration contract:
//
// New(Config) defaults to StateDir/fleet.sqlite and its lifetime singleton lock. Token
// is an optional all-scope operator; Identities are tenant/app-scoped operators.
// Targets are explicit bootstrap enrollments with unique bearer tokens. Removing
// an enrollment persists a revocation; reusing an ID for another scope is refused.
// Config.AllowEffects and AgentConfig.AllowEffects default false. Both are trusted
// bootstrap admission, never request fields. Stage, startup/restore and activation
// compile with that admission. GET capabilities reports the controller setting.
// Admission produces inert intents only; the separate broker must authorize each
// effect scope/receipt against its own runtime grants. Fleet grants no broker rights.
// Config.DatabaseURL selects PostgreSQL and is mutually exclusive with StateDir.
// DatabaseNamespace defaults to netcap_firewall_fleet. Use one dedicated schema
// per fleet, with identical bootstrap identities/admission/rollout configuration
// on every replica; a persisted fingerprint rejects drift before state mutation.
// Bootstrap changes require an explicit coordinated operator migration, not a
// rolling config change. Database URLs are secrets; nonloopback requires TLS
// sslmode=verify-full. The lib/pq dependency is v1.12.3.
// Every PG transaction takes a namespace advisory lock under READ COMMITTED,
// then reloads snapshot and immutable artifacts. No ambiguous commit is retried.
// This provides active-active application coordination against one writable PG
// authority; primary fencing, synchronous replication and failover endpoints are
// the database operator's responsibility. It is not distributed atomic activation.
//
// Mount Handler on a dedicated, timeout-bounded TLS listener. REST paths below
// /api/v1/fleet are GET capabilities/status/audit/desired and POST stage/rollout/
// activate/promote/rollback/drain/revoke/resume/ack. Operators select scope {tenant,app}; desired/ack accept
// only target tokens and derive attachment server-side. /mcp exposes fleet_*
// tools through the same authenticated listener. Scoped operator identities can
// omit scope. Execute is the equivalent in-process authenticated operator API.
//
// Stage returns an immutable revision. Rollout requires a unique job ID, staged
// revision, target IDs, expected generation per target, optional canary subset,
// and an RFC3339 deadline within 24 hours. Activate CASes expected_phase=staged;
// promote requires expected_phase=canary plus successful observed canary acks.
// Rollback CASes canary/active and each applied target's generation, restoring
// previous revisions at NEW generations. A target without a previous initialized
// revision cannot roll back. Expired jobs cannot activate/promote. Rollback has a
// fresh 24-hour distribution deadline. RollbackOnFailure on Config or the rollout
// request enables a durable gate; a request cannot disable a configured gate.
// Guarded jobs require initialized previous revisions. A matching failed health
// ack rolls back applied targets immediately. Missed deadlines roll back pending
// canaries or unconverged active jobs; healthy converged active jobs stay installed.
// Maintain(ctx) is bounded to 128 jobs; main must schedule it when traffic is idle.
// Scoped status/desired/ack also drive maintenance. Conflicting generations or
// drain/revoke controls produce audited rollback_blocked status, never overwrite.
// Status exposes deadlines, desired/observed generations, heartbeat time and errors.
// Audit retains the last 2048 successful mutation/ack records. Capacity limits
// reject new work; they never silently evict rollback artifacts or live jobs.
// Metadata snapshots are capped at 16 MiB; immutable artifacts remain separate.
// Drain/revoke/resume require target IDs and an expected generation per target.
// Each control advances generation. Revoke survives bootstrap reload and withholds
// policy artifacts; its token can only fetch/ack its own drain envelope. Resume is
// an explicit scoped CAS operation and requires an initialized revision. Unreachable
// workers cannot be remotely drained until contact; use positive MaxStale to bound
// offline readiness. Control acknowledgments are separate from policy application.
//
// Run(ctx, AgentConfig, Target) owns SetPolicy. The target must atomically publish
// compiled pointers. Set the main runtime draining before Run, then drive it from
// OnStatus.Ready. OnStatus is required and must apply draining synchronously before
// returning; drain receipts are sent only after persistence and that callback.
// Callbacks must return promptly. Draining/Revoked status is never
// ready. The HMAC cache binds identity AND AllowEffects, and preserves drain/revoke
// controls across offline restart. Valid identity-bound HMAC cache
// can initialize offline. MaxStale=0 retains last known policy indefinitely;
// positive MaxStale expires readiness independently of blocked GET/ACK calls.
// Status callbacks are serialized and the watchdog is joined before Run returns.
// Shutdown publishes terminal Ready=false with categorical cancellation/stop errors.
// An already-cancelled context returns before cache recovery, target mutation or
// status callbacks. Later cancellation is checked at each apply/publication
// decision; it cannot be made atomic with an external SetPolicy/callback call.
// Fresh verified/persisted contact can resume a nonrevoked policy before ACK;
// readiness is not proof of controller-observed convergence. No valid cache and no
// controller means unready, regardless of Target.Policy's initial value.
//
// Backup(ctx, absolutePath) creates a consistent private SQLite snapshot. For
// manual recovery, fence the old host first, call firewallstate.Restore with name
// "fleet" into an empty private StateDir, then New with the bootstrap identities.
// Agents reject generation regressions from stale restores. SQLite provides no
// multi-controller active/active HA; ack convergence is not globally atomic
// activation and does not drain in-flight requests under older revisions.
// PostgreSQL rejects this Backup API; use pg_dump/native database backups.
// Real PG17 tests use NETCAP_POSTGRES_TEST_URL. Crash tests additionally require
// NETCAP_POSTGRES_TEST_CONTAINER=ncf-ha-* with label netcap.firewall.ha-test=true,
// and a fixed published 127.0.0.1 port (ephemeral Docker ports change on restart).
// Run crash-enabled package suites with go test -p=1 so the shared test database
// is not restarted underneath another package's integration tests.
