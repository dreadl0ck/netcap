/*
Package waf spools and inspects complete HTTP requests before opening an upstream
request. MaxConcurrent bounds admitted requests, including long-lived responses
and upgraded connections. MaxBodyBytes bounds wire and expanded request bytes;
MaxResponseBytes applies only with InspectResponse. Limits are 1..64 MiB per wire
and expanded representation. Spools spill above 64 KiB to private temporary files;
reference-counted views retain files until both inspection and forwarding finish.
NativeBodyBytes reserves metadata headroom within policy.MaxEventBytes (2 MiB).
Body-dependent policies reject larger bodies, never truncated projections. Compiled
RequiresBody(phase string) bool metadata permits larger body-independent traffic;
without that capability every phase conservatively requires Body. JSON, XML and
URL-encoded bodies additionally enforce NativeBodyBytes to bound scalar allocation.
Multipart files and opaque bodies can use the complete configured spool limit.
BodyCapabilities reports these bounds. Coraza owns additional internal buffers;
its response buffer is memory-backed up to MaxResponseBytes, not a shared spool.
MaxBufferedBytes defaults to 64 MiB and cannot exceed 1 GiB. One runtime budget
covers HTTP spool contents/scratch, native projections, Coraza reservations and
both message directions. Exhaustion rejects locally with 503 or terminates a
message stream before releasing its frame. Shared views retain their quota until
the final close; failed partial spools remove their files. This is retained-byte
accounting, not an operating-system RSS limit; library/allocator overhead remains.
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
forwarding in the base handler. MessageHandler explicitly enables independent
WebSocket and HTTP/2 gRPC message gates instead, with a 1 MiB wire/expanded message
limit, no WebSocket compression, and identity/gzip gRPC encoding. Native and Coraza
inspection finish before any message frame header is released. InspectResponse spools
and bounds complete responses and rejects upgrades; it is incompatible with
unbounded response streams. Native evaluation errors fail closed: HTTP 503 in the
base handler, or stream termination in message mode.

SetPolicy atomically replaces policy for subsequent inspection snapshots. Each
admitted request uses one snapshot for both phases. Config is immutable after
New. SetEvaluator installs one bootstrap-only hook and receives that same compiled
snapshot for every native phase/message/trailer. Default evaluation is Compiled.Evaluate.
The shared guard's default request unit counts initial request headers once;
message unit counts request messages. Trailer and response events still reach
the hook for native evaluation. Message payloads are borrowed
as bytes, with a native Body string created only for body-dependent phases.
SetDraining rejects new requests and makes readiness fail. Close also
cancels active proxy exchanges, closes upgraded clients and evicts idle upstream
connections. Callers still own Server.Shutdown and accepted idle client sockets.
SetReadinessCheck installs one bootstrap-only, concurrency-safe cached dependency
predicate. Readiness ANDs it with policy availability, draining and lifetime state;
resuming a drained listener cannot clear an unhealthy dependency. Admin probes
also freeze bootstrap hooks. A readiness predicate must not initiate network I/O.

CorazaCRS additionally requires the coraza build tag, coraza/v3 v3.8.1 and
coraza-coreruleset/v4 v4.25.0. Without that tag enabling it fails startup. Its
audit/debug sinks are disabled; only outer redacted decisions are queued.
*/
package waf
