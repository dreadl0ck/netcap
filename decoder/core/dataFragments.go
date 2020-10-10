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

// TODO: implement a read that does not duplicate the data, but instead iterates over the fragments when being read from
func (d DataFragments) reader() io.Reader {
	return bytes.NewReader(d.bytes())
}

// First returns the first fragment.
func (d DataFragments) First() []byte {
	if len(d) > 0 {
		return d[0].Raw()
	}
	return nil
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
