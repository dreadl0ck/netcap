package firewallstate

// Integration contract:
//
// New(Config) opens StateDir/sharedstate.sqlite. Principals bind unique tokens
// to server-side tenant/app scopes; the HTTP body cannot select a scope. Mount
// Handler on a timeout-bounded TLS listener. POST /api/v1/state/count accepts
// {"key":{"revision":"<64 hex>","group":"<64 hex>"},
//  "window":{"mode":"fixed","duration":60000000000}}.
// Duration is nanoseconds (1ms..24h). Fixed windows start at the first count and
// do not extend on hits; sliding windows are rejected. A transactional persisted
// clock high-water mark clamps backward server time, including after restart;
// rollback cannot reopen or extend windows. Server time is authoritative.
// Count increments one key transactionally and returns {count,expires}. Expired
// keys can be reclaimed. At capacity, new keys fail with 503; live keys are never
// evicted. Multiple principals in the same tenant/app deliberately share counters.
// Config.DatabaseURL selects PostgreSQL instead; StateDir must then be empty.
// DatabaseNamespace defaults to netcap_firewall_state. Active replicas must use
// the same namespace, principals/scopes/tokens and MaxKeys; persisted bootstrap
// fingerprints reject drift. PostgreSQL uses namespace advisory transaction locks
// under READ COMMITTED, protects global capacity, and reads clock_timestamp()
// inside each count transaction. There is no instance-local counter cache or
// affinity requirement. Ambiguous commits are never automatically retried.
// Nonloopback requires sslmode=verify-full. Session configuration pins the schema,
// synchronous_commit=on and 5s statement/lock/idle-transaction limits; environment
// options cannot redirect the endpoint/schema or disable those limits. Health
// rejects read-only/standby connections and discards unwritable pooled sessions.
// Database failover/fencing and replication
// durability remain PostgreSQL operator responsibilities. URLs are never logged.
//
// NewClient(ClientConfig) implements Store. Count never retries an ambiguous POST;
// callers must fail closed on error. Bind is only for trusted in-process callers.
// Client.Probe and bound-store Probe use GET /api/v1/state/health or live local SQL.
// Health requires principal authentication, refuses Origin, and returns {ready:true}
// only after a bounded metadata read. It never counts, prunes or advances the clock.
// NewGuard(GuardConfig) supplies a standalone request-phase shared rate guard:
// GuardConfig.Unit is bootstrap-only: "request" (default) or "message". Request
// counts inspection.kind="headers" and legacy events without that attribute;
// message counts only inspection.kind="message". Trailers and response events
// never count. Both units still run native Evaluate for skipped events. Unknown
// units/kinds fail closed. Guard ID, unit, grouping and revision isolate counters.
// Evaluate(ctx, compiledPolicy, event) counts before native Evaluate, returning
// deny/429 above Limit and deny/503 plus error on shared-state failure. Response
// phase runs native Evaluate without recounting. GroupBy is empty/global,
// ClientIP, Host, Method or Path. This is an always-enforcing external guard, not
// a replacement for native policy rule thresholds or sequences. Revision and
// guard ID/unit/group hash isolate counters. Guard.Probe(ctx) supports startup and
// periodic readiness checks without quota consumption. Ready starts unready; only
// the most recently started count/probe can publish its outcome, so late older
// completions cannot clear newer failures. Stores lacking Probe return "store cannot probe" without
// falling back to Count. Runtime JSON GuardConfig can be owned by the CLI.
//
// Backup creates a private consistent SQLite snapshot. Restore(ctx, backup,
// emptyStateDir, "sharedstate") requires the old host to be fenced first. New
// validates the restored schema, scopes, keys and bounds. A backup has counters
// only through its snapshot time; manual restore is not lossless active/active
// HA. Strong increments apply to one authoritative instance, with no affinity
// claim or consistency across independently restored services.
// For PostgreSQL, Backup returns an explicit error; use pg_dump/native backups.
// Real integration tests require NETCAP_POSTGRES_TEST_URL and an actual loopback
// PostgreSQL 17 server; subprocess tests verify cross-process serialization.
