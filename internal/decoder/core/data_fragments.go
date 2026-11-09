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

package core

import (
	"bytes"
	"github.com/dreadl0ck/netcap/internal/packetview"
	"io"
	"time"
)

// DataFragments implements sort.Interface to sort data fragments based on their timestamps.
type DataFragments []dataFragment

// MergeByTimestamp interleaves two per-direction fragment slices by capture
// timestamp into a newly allocated slice.
//
// The merge is stable: a fragment never moves relative to the other fragments
// of the same input. Both inputs are in stream (byte) order by construction,
// but their timestamps are not monotonic, because reassembly delivers the
// packet that closed a hole together with the earlier-captured packets it had
// queued. Sorting the concatenation instead reorders bytes within a direction
// and corrupts every consumer that reads the result as a byte stream.
//
// Equal timestamps use capture ordinals when available; otherwise a precedes b.
func MergeByTimestamp(a, b DataFragments) DataFragments {
	merged := make(DataFragments, 0, len(a)+len(b))

	var i, j int
	for i < len(a) && j < len(b) {
		if FragmentBefore(b[j], a[i]) {
			merged = append(merged, b[j])
			j++

			continue
		}

		merged = append(merged, a[i])
		i++
	}

	merged = append(merged, a[i:]...)

	return append(merged, b[j:]...)
}

// fragmentTimestamp returns the capture timestamp of a fragment,
// or the zero time if it carries no assembler context.
func fragmentTimestamp(d dataFragment) time.Time {
	if ctx := d.Context(); ctx != nil {
		return ctx.GetCaptureInfo().Timestamp
	}

	return d.CaptureInfo().Timestamp
}

// FragmentBefore uses original capture order to disambiguate coarse timestamps.
// It is used only between directions; stream byte order remains authoritative.
func FragmentBefore(a, b dataFragment) bool {
	at, bt := fragmentTimestamp(a), fragmentTimestamp(b)
	if !at.Equal(bt) {
		return at.Before(bt)
	}
	ordinal := func(d dataFragment) uint64 {
		ci := d.CaptureInfo()
		if c := d.Context(); c != nil {
			ci = c.GetCaptureInfo()
		}
		if c := packetview.FromCapture(ci); c != nil && len(c.Packets) > 0 {
			return c.Packets[0].Ordinal
		}
		return 0
	}
	x, y := ordinal(a), ordinal(b)
	return x != 0 && y != 0 && x < y
}

// Size returns the fragments total data size.
func (d DataFragments) Size() int {
	var s int
	for _, dt := range d {
		s += len(dt.Raw())
	}
	return s
}

// Bytes returns all fragment data concatenated into a single byte slice.
func (d DataFragments) Bytes() []byte {
	var b bytes.Buffer

	for _, dt := range d {
		b.Write(dt.Raw())
	}

	return b.Bytes()
}

// ContiguousBytes returns the first observed byte run without joining across loss.
// A leading loss marker is permitted; it cannot bridge two observed byte ranges.
func (d DataFragments) ContiguousBytes() []byte {
	var b bytes.Buffer
	for _, fragment := range d {
		if fragment == nil {
			continue
		}
		if stream, ok := fragment.(*StreamData); ok && (stream.SkippedBytes != 0 || stream.DiscardedBytes > 0) && b.Len() > 0 {
			break
		}
		b.Write(fragment.Raw())
	}
	return b.Bytes()
}

// reader returns a reader that iterates over the fragments without copying data.
func (d DataFragments) reader() io.Reader {
	readers := make([]io.Reader, len(d))
	for i, dt := range d {
		readers[i] = bytes.NewReader(dt.Raw())
	}
	return io.MultiReader(readers...)
}

// First returns the first fragment.
func (d DataFragments) First() []byte {
	if len(d) > 0 {
		return d[0].Raw()
	}
	return nil
}

// FirstNonEmpty returns the first fragment that carries bytes.
//
// Reassembly prepends a zero-length marker when a direction begins midstream
// with no observed SYN, so First returns no bytes for every such conversation.
// Protocol detection run on that marker rejects the real protocol and then
// admits whichever decoder accepts an empty stream.
func (d DataFragments) FirstNonEmpty() []byte {
	for _, dt := range d {
		if raw := dt.Raw(); len(raw) > 0 {
			return raw
		}
	}

	return nil
}

// SourceIP returns the source IP address from the first fragment's network layer.
// Returns empty string if no fragments are available.
func (d DataFragments) SourceIP() string {
	if len(d) > 0 {
		return d[0].Network().Src().String()
	}
	return ""
}

// Len returns the length.
func (d DataFragments) Len() int {
	return len(d)
}

// Less will check if the value at index i is less than the one at index j.
func (d DataFragments) Less(i, j int) bool {
	return FragmentBefore(d[i], d[j])
}

// Swap will flip both values.
func (d DataFragments) Swap(i, j int) {
	d[i], d[j] = d[j], d[i]
}
