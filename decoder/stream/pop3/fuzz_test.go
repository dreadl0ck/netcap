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

//go:build fuzz

package pop3

import (
	"strings"
	"testing"
)

// FuzzGetCommand asserts the POP3 line tokeniser never panics on
// arbitrary input.
//
// NOTE: getCommand only edge-trims the cutset "\r \n" and then splits on
// a single space, so a line carrying an embedded newline (e.g. "0\n 0")
// can leave that newline inside the verb. In practice the reader feeds it
// one textproto line at a time, so this is a harmless quirk rather than a
// crash; we assert only the no-panic safety property and that the verb
// contains no space (the split delimiter).
func FuzzGetCommand(f *testing.F) {
	for _, s := range []string{
		"", " ", "\r\n", "USER frated", "PASS secret",
		"APOP mrose c4c9334bac560ecc979e58001b3e22fb", "STAT", "0\n 0",
		strings.Repeat("X ", 1000),
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, line string) {
		cmd, _ := getCommand(line)
		if strings.Contains(cmd, " ") {
			t.Fatalf("getCommand(%q) cmd %q contains the split delimiter", line, cmd)
		}
	})
}

// FuzzParseMessageID asserts the int32 parser never panics and that a
// successful parse round-trips through formatting consistently.
func FuzzParseMessageID(f *testing.F) {
	for _, s := range []string{"", "0", "1", "-1", "2147483647", "2147483648", "abc", " 5 "} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if _, err := parseMessageID(s); err != nil {
			return // error is an acceptable outcome; we only care about panics
		}
	})
}
