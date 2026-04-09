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
	"io"
)

// DataFragments implements sort.Interface to sort data fragments based on their timestamps.
type DataFragments []dataFragment

// Size returns the fragments total data size.
func (d DataFragments) Size() int {
	var s int
	for _, dt := range d {
		s += len(dt.Raw())
	}
	return s
}

func (d DataFragments) bytes() []byte {
	var b bytes.Buffer

	for _, dt := range d {
		b.Write(dt.Raw())
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
	data1 := d[i]
	data2 := d[j]

	if data1.Context() == nil || data2.Context() == nil {
		return false
	}

	return data1.Context().GetCaptureInfo().Timestamp.Before(data2.Context().GetCaptureInfo().Timestamp)
}

// Swap will flip both values.
func (d DataFragments) Swap(i, j int) {
	d[i], d[j] = d[j], d[i]
}
