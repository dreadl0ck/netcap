package policycontrol

// Administrative HTTP contract (all paths require Authorization: Bearer <Token>):
//
//   GET  /api/v1/policy/capabilities
//   GET  /api/v1/policy/revisions                 retained revision IDs
//   GET  /api/v1/policy/revision?revision=<id>    omitted ID selects active
//   GET  /api/v1/policy/audit?limit=<count>       newest first; default 100
//   POST /api/v1/policy/revisions                stage (alias: /stage)
//   POST /api/v1/policy/check
//   POST /api/v1/policy/evaluate
//   POST /api/v1/policy/diff
//   POST /api/v1/policy/activate
//   POST /api/v1/policy/rollback
//   POST /mcp                                   stateless streamable HTTP
//
// POST bodies use Request. Bundle is a JSON/YAML document encoded as a string.
// Mutations require idempotency_key (or the HTTP Idempotency-Key header).
// Activate requires revision and expected_revision. Rollback requires
// expected_revision; an omitted revision selects the previous deployment.
// Idempotency receipts retain the last MaxReceipts successful mutation keys;
// clients must not reuse older keys. Stage, activate, rollback and their audit
// records commit together; retries do not add audit records or reset counters.
// Read-only services keep no administrative history or staged revisions.
//
// Set Config.Managed=true and StateDir explicitly for managed mode. A service
// requires a private StateDir (0700) and regular private state files (0600).
// It owns Target.SetPolicy until Close. Runtime bootstrap, listeners and upstreams
// are deliberately outside Target. The caller owns the administrative listener:
// configure TLS, header/body read timeouts and write timeouts on http.Server.
// Synthetic evaluation accepts events (at most MaxEvents), preserves threshold
// state within each ordered replay, and never changes live counters. The legacy
// event field returns one decision; events returns an array. Do not combine them.
// Activation/rollback to a different revision and managed restart reset runtime
// counters. Same-revision activation and receipt replay preserve current state.
// HTTP rejects browser Origin headers and unsupported MCP protocol versions;
// omitted MCP version headers use the SDK's 2025-03-26 compatibility behavior.
// Request contexts cancel pending operations; a committed deployment is durable
// even if the client disconnects before receiving its receipt.
