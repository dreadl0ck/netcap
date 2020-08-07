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
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
	"time"
)

var softwareTests = []regexTest{
	{
		name:     "Windows Netcat",
		input:    "Test123\nMicrosoft Windows [Version 10.0.10586]\n(c) 2015 Microsoft Corporation. All rights reserved. \nC:\\cygwin\\netcat>",
		expected: "Microsoft Windows [Version 10.0.10586]",
	},
	{
		name:     "Apache Test",
		input:    "Hello,\nfor our hosting we will use Apache version 2.4.29.\nThere are other options,\nlike Lighttp 2.3.4",
		expected: "for our hosting we will use Apache version 2.4.29.-like Lighttp 2.3.4", // multiple values can be expected when separated with - TODO: refactor to use an array
	},
	{
		name:     "NginX Test",
		input:    "We will test\ncan we detect NginX v2.3.4\nI hope so\nwe'll see",
		expected: "can we detect NginX v2.3.4",
	},
	{
		name:     "NginX Test",
		input:    "We will test\ncan we detect NginX version 2.3.4\nI hope so\nwe'll see",
		expected: "can we detect NginX version 2.3.4",
	},
}

func (r regexTest) testSoftwareHarvester(t *testing.T) {
	s := softwareHarvester([]byte(r.input), "", time.Now(), "test", "test", []string{})

	parts := strings.Split(r.expected, "-")

	if len(s) != len(parts) {
		t.Fatal("Expected:", len(parts), " found: ", len(s), " results", "expected value", r.expected, "input", r.input)
	}

	for i, p := range parts {
		if p != s[i].Notes {
			fmt.Println("length expected", len(p))
			fmt.Println(hex.Dump([]byte(p)))
			fmt.Println("length received", len(s[i].Notes))
			fmt.Println(hex.Dump([]byte(s[i].Notes)))
			t.Fatal("Expected: ", conf, " Received: ", s[i].Notes, "all:", s[i])
		}
	}
}

func TestGenericVersionHarvester(t *testing.T) {
	for _, r := range softwareTests {
		r.testSoftwareHarvester(t)
	}
}
