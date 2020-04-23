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

package netcap

import (
	"github.com/dreadl0ck/netcap/types"
	"io"
	"testing"
)

func TestReader(t *testing.T) {
	r, err := Open("tests/TCP.ncap.gz", DefaultBufferSize)
	if err != nil {
		t.Fatal(err)
	}

	header := r.ReadHeader()
	if header == nil {
		t.Fatal("header is nil")
	}

	if header.Type != types.Type_NC_TCP {
		t.Fatal("not TCP, got: ", header.Type)
	}

	var (
		tcp   = InitRecord(header.Type)
		count int
	)

	for {
		err = r.Next(tcp)
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			break
		} else if err != nil {
			t.Fatal(err)
		}
		count++
	}

	if count != 3196 {
		t.Fatal("expected 3196 audit records, got: ", count)
	}
}
