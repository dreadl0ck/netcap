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

package software

import (
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
	"time"

	decoderconfig "github.com/dreadl0ck/netcap/decoder/config"
)

type regexTest struct {
	name     string
	input    string
	expected string
}

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
			t.Fatal("Expected: ", decoderconfig.DefaultConfig, " Received: ", s[i].Notes, "all:", s[i])
		}
	}
}

func TestGenericVersionHarvester(t *testing.T) {
	for _, r := range softwareTests {
		r.testSoftwareHarvester(t)
	}
}

// https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Server
func TestRegexpServerName(t *testing.T) {
	values := regExpServerName.FindStringSubmatch("Apache/2.4.1 (Unix)")

	if values[1] != "Apache" {
		t.Fatal("expected value Apache, got:", values[1])
	}

	if values[2] != "2.4.1" {
		t.Fatal("expected value 2.4.1, got:", values[2])
	}

	if values[3] != "Unix" {
		t.Fatal("expected value Unix, got:", values[3])
	}
}

func TestRegexpXPoweredBy(t *testing.T) {
	values := regexpXPoweredBy.FindStringSubmatch("PHP/5.2.17")

	if values[1] != "PHP" {
		t.Fatal("expected value PHP, got:", values[1])
	}

	if values[2] != "5.2.17" {
		t.Fatal("expected value 5.2.17, got:", values[2])
	}

	values = regexpXPoweredBy.FindStringSubmatch("ASP.NET")

	if values[1] != "ASP.NET" {
		t.Fatal("expected value ASP.NET, got:", values[1])
	}

	if values[2] != "" {
		t.Fatal("expected value empty string, got:", values[2])
	}

	values = regexpXPoweredBy.FindStringSubmatch("UrlRewriter.NET 2.0.0")

	if values[1] != "UrlRewriter.NET" {
		t.Fatal("expected value UrlRewriter.NET, got:", values[1])
	}

	if values[2] != "2.0.0" {
		t.Fatal("expected value 2.0.0, got:", values[2])
	}
}
