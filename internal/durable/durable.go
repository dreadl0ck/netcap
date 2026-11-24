// Package durable flushes a capture's output once, before it is reported
// complete, instead of syncing every derived file.
//
// Per-file fsync made stream-heavy captures spend minutes in sync calls
// (Blank-Slate: about 90,700 syncs, 591 s on try.netcap.io). Outputs are
// published by rename, so readers never see partial directories; the barrier
// decides when they survive an OS crash or power loss.
package durable

// Barrier makes everything written under dir durable before a completion
// marker is written. Linux syncs the whole filesystem holding dir (syncfs),
// which also covers directory entries. Elsewhere it does nothing: completion
// markers are written with os.File.Sync, which on macOS is F_FULLFSYNC, and
// after a power loss shortly before completion outputs may be truncated; their
// readers verify sizes and hashes, and a re-run rebuilds them.
func Barrier(dir string) error { return barrier(dir) }
