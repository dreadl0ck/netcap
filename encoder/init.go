// +build darwin,linux

/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) 2017 Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

package encoder

import "syscall"

/*
 *	Package Level Initialization
 */

func init() {

	// collect all names for layer encoders on startup
	for _, e := range layerEncoderSlice {
		allEncoderNames[e.Layer.String()] = struct{}{}
	}

	// get system block size for use as the buffer size of the buffered Writers
	var stat syscall.Statfs_t
	if err := syscall.Statfs("/", &stat); err != nil {
		panic(err)
	}

	// set block size
	BlockSize = int(stat.Bsize)
}
