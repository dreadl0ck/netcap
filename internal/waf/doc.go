/*
Package waf buffers and inspects complete HTTP requests before opening an upstream
request. MaxConcurrent bounds admitted requests, including long-lived responses
and upgraded connections. MaxBodyBytes bounds wire and expanded request bytes;
MaxResponseBytes applies only with InspectResponse. Buffers, policy strings and
optional Coraza transactions introduce a constant-factor memory overhead.
Both configured body limits must be 1..1048576 bytes (1 MiB), reserving metadata
headroom within policy.MaxEventBytes (2 MiB). Larger uploads are unsupported.
Inspection headers are bounded to 32 KiB, 128 names and 1024 values; each routing
field is bounded to 65536 bytes. Oversized request metadata receives 414/431;
oversized upstream headers receive 502 before any origin response is forwarded.
JSON/XML nesting is capped at 64 and parsed argument/part entries at 1000.
Structural validation runs before disruptive rules, including in monitor mode.

The caller owns listeners and http.Server configuration. Set ReadHeaderTimeout,
MaxHeaderBytes, IdleTimeout and shutdown deadlines there. BodyTimeout bounds the
incoming body, upstream exchange through response headers, and opted-in response
buffering. A blanket server WriteTimeout also terminates streaming responses.
Bind AdminHandler to a private/authenticated listener. Run WriteAudit separately
with an owned context and writer; slow audit consumers cause counted drops.

Default response coverage is status and headers only, before forwarding final
headers. Bodies and trailers are streamed without inspection; WebSocket frames
are tunneled after an inspected handshake. Request bodies must finish before
forwarding, so client-streaming and bidirectional gRPC are unsupported. This is
an HTTP reverse proxy, not a native protocol inspector. InspectResponse buffers
and bounds complete responses and rejects upgrades; it is incompatible with
unbounded response streams. Native evaluation errors always produce local 503.

SetPolicy atomically replaces policy for subsequent inspection snapshots. Each
admitted request uses one snapshot for both phases. Config is immutable after
New. SetDraining rejects new requests and makes readiness fail. Close also
cancels active proxy exchanges, closes upgraded clients and evicts idle upstream
connections. Callers still own Server.Shutdown and accepted idle client sockets.

CorazaCRS additionally requires the coraza build tag, coraza/v3 v3.8.1 and
coraza-coreruleset/v4 v4.25.0. Without that tag enabling it fails startup. Its
audit/debug sinks are disabled; only outer redacted decisions are queued.
*/
package waf
