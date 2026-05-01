//go:build !hyperscan

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

package hsmatch

import "errors"

// Enabled reports whether this build was compiled with Hyperscan support.
const Enabled = false

// Version returns "disabled" in stub builds.
func Version() string { return "disabled" }

// ErrDisabled is returned by every entry point in this stub build.
var ErrDisabled = errors.New("hsmatch: hyperscan support not compiled in (rebuild with -tags hyperscan)")

// ErrClosed mirrors the tagged-build sentinel; never produced here.
var ErrClosed = errors.New("hsmatch: database closed")

// Flag is a no-op type so callers can declare flags unconditionally.
type Flag uint32

// Flag values are placeholders so that callers can reference them in tagged
// and untagged builds alike.
const (
	FlagCaseless Flag = 1 << iota
	FlagDotAll
	FlagMultiLine
	FlagSingleMatch
	FlagAllowEmpty
	FlagUtf8
	FlagPrefilter
	FlagSomLeftMost
)

// Pattern mirrors the tagged-build type.
type Pattern struct {
	ID    int
	Expr  string
	Flags Flag
}

// Hit mirrors the tagged-build type.
type Hit struct {
	ID   int
	From uint64
	To   uint64
}

// Rejection mirrors the tagged-build type.
type Rejection struct {
	Index  int
	ID     int
	Expr   string
	Reason string
}

// Stats mirrors the tagged-build type.
type Stats struct {
	Patterns   int
	Rejections int
	Matches    uint64
	Scans      uint64
	ScanErrors uint64
}

// DB is an opaque placeholder; all methods report ErrDisabled.
type DB struct{}

// Compile reports every supplied pattern as rejected and returns ErrDisabled.
//
// Callers are expected to check `Enabled` (or the returned error) and fall
// back to their pre-existing regex engine.
func Compile(patterns []Pattern) (*DB, []Rejection, error) {
	if len(patterns) == 0 {
		return nil, nil, ErrDisabled
	}
	rejections := make([]Rejection, len(patterns))
	for i, p := range patterns {
		rejections[i] = Rejection{
			Index:  i,
			ID:     p.ID,
			Expr:   p.Expr,
			Reason: ErrDisabled.Error(),
		}
	}
	return nil, rejections, ErrDisabled
}

// Match always returns ErrDisabled.
func (d *DB) Match(_ []byte, _ func(Hit) error) error { return ErrDisabled }

// Stats always returns the zero value in stub builds.
func (d *DB) Stats() Stats { return Stats{} }

// Close is a no-op.
func (d *DB) Close() error { return nil }
