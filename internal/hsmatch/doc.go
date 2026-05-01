/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

// Package hsmatch is a thin, build-tag gated wrapper around the gohs
// (Hyperscan / Vectorscan) library.
//
// It exposes a small block-mode multi-pattern matcher used by netcap to
// pre-filter input buffers before running heavier RE2 / regexp2 matchers
// for capture-group extraction.
//
// Build behaviour
//
//   - Default builds (no tag): a stub implementation is compiled. All exported
//     functions return ErrDisabled and callers fall back to their existing
//     regex engine. Zero CGO / C library dependencies.
//   - With `-tags hyperscan`: the real implementation backed by
//     github.com/flier/gohs is compiled. Requires libhs (Intel Hyperscan on
//     x86_64 or VectorCamp Vectorscan on ARM/macOS) discoverable via
//     pkg-config (libhs.pc).
//
// Hyperscan does not return submatch offsets – only the (id, from, to) of
// the overall match. The intended usage pattern is therefore:
//
//  1. Compile a [DB] from many [Pattern]s once at startup.
//  2. For each input buffer call [DB.Match]; collect the IDs that hit.
//  3. For each hit, run the original capture-aware regex (RE2 / regexp2)
//     to extract groups – but only for the small set of patterns that
//     actually matched, not the full pattern list.
//
// Patterns that Hyperscan refuses to compile (e.g. because they use
// backreferences or other PCRE-only features) are reported via the
// `rejections` slice returned from [Compile] – including the original
// pattern index, expression and the libhs/gohs error message – so the
// caller can keep these on the existing regex engine and surface useful
// diagnostics in logs and the web UI.
//
// Runtime counters (scans, matches, scan errors) are exposed through
// [DB.Stats]; the optional integration in
// `decoder/stream/service` aggregates them into a JSON-friendly
// HyperscanStatus that the web UI exposes at GET /api/hyperscan.
package hsmatch
