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

package encoder

import (
	"encoding/binary"
	"testing"
)

func TestParseSSHKexInitMsgLength(t *testing.T) {
	// FYI: parseInt handles hex strings as well: strconv.ParseInt("0x00000634", 0, 64)
	if binary.BigEndian.Uint32([]byte{0x00, 0x00, 0x06, 0x34}) != 1588 {
		t.Fatal("expected 1588")
	}
}

func TestParseSSHKexInitMsgPadding(t *testing.T) {
	if uint8(0x06) != 6 {
		t.Fatal("the value should be 6")
	}
}
