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
	"strings"
	"testing"
	"time"
)

var softwareTests = []regexTest{
	{
		name:     "Windows Netcat",
		input:    "Test123\nMicrosoft Windows [Version 10.0.10586]\n(c) 2015 Microsoft Corporation. All rights reserved. \nC:\\cygwin\\netcat>",
		expected: "Microsoft Windows-Version 10.0.10586",
	},
}

func (r regexTest) testSoftwareHarvester(t *testing.T) {
	s := softwareHarvester([]byte(r.input), "", time.Now(), "test", "test", []string{})
	if len(s) != 1 {
		t.Fatal("incorrect number of results, expected 1 but got", len(s))
	}

	parts := strings.Split(r.expected, "-")
	if len(parts) != 2 {
		t.Fatal("invalid format for expected field")
	}

	for _, soft := range s {
		if soft.Product != parts[0] || soft.Version != parts[1] {
			t.Fatal("incorrect result:", soft.Product, soft.Version, "expected", parts)
		}
	}
}

func TestGenericVersionHarvester(t *testing.T) {
	for _, r := range softwareTests {
		r.testSoftwareHarvester(t)
	}
}