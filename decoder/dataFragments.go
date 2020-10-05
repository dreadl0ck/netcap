/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) 2017-2020 Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

package decoder

import (
	"bytes"
)

// dataFragments implements sort.Interface to sort data fragments based on their timestamps.
type dataFragments []dataFragment

func (d dataFragments) size() int {
	var s int
	for _, dt := range d {
		s += len(dt.raw())
	}
	return s
}

func (d dataFragments) bytes() []byte {
	var b bytes.Buffer

	for _, dt := range d {
		b.Write(dt.raw())
	}

	return b.Bytes()
}

// Len returns the length.
func (d dataFragments) Len() int {
	return len(d)
}

// Less will check if the value at index i is less than the one at index j.
func (d dataFragments) Less(i, j int) bool {
	data1 := d[i]
	data2 := d[j]

	if data1.context() == nil || data2.context() == nil {
		return false
	}

	return data1.context().GetCaptureInfo().Timestamp.Before(data2.context().GetCaptureInfo().Timestamp)
}

// Swap will flip both values.
func (d dataFragments) Swap(i, j int) {
	d[i], d[j] = d[j], d[i]
}
