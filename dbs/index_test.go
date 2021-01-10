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

package dbs

import (
	"testing"
)

func TestIntermediatePatchVersions(t *testing.T) {
	versions := []string{"4.5.7", "4.5.8", "4.5.9", "4.5.10", "4.5.11"}
	generated := intermediatePatchVersions("4.5.6", "4.5.12")

	for i := 0; i < len(versions); i++ {
		if versions[i] != generated[i] {
			t.Fatal("expected ", versions[i], ", got ", generated[i])
		}
	}
}

func TestYearRange(t *testing.T) {
	y := yearRange(2017, 2020)
	expected := []string{"2017", "2018", "2019", "2020"}

	for i, elem := range expected {
		if elem != y[i] {
			t.Fatal(elem, " != ", y[i])
		}
	}
}
