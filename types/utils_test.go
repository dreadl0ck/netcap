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

package types

import (
	"testing"
)

func TestIPToInt64(t *testing.T) {
	if ipToInt64("127.0.0.1") != 2130706433 {
		t.Fatal("unexpected result")
	}
	if ipToInt64("127.0.0.2") != 2130706434 {
		t.Fatal("unexpected result")
	}

	if ipToInt64("2001:db8:85a3:8d3:1319:8a2e:370:7348") != 1376283091369227080 {
		t.Fatal("unexpected result")
	}

	// TODO: this way, half of the address is ignored...
	if ipToInt64("2001:db8:85a3:8d3:1319:8a2e:370:7348") == ipToInt64("ffff:ffff:ffff:ffff:1319:8a2e:370:7348") {
		t.Fatal("TODO: come up with a better way for a numeric representation of IPv6 addrs")
	}
}

func TestMacToUint64(t *testing.T) {
	if macToUint64("02:f5:53:d3:82:70") != 4626045091369414704 {
		t.Fatal("unexpected result", macToUint64("02:f5:53:d3:82:70"))
	}
	if macToUint64("02:f5:53:d3:82:71") != 4626045091369414705 {
		t.Fatal("unexpected result", macToUint64("02:f5:53:d3:82:71"))
	}
}
