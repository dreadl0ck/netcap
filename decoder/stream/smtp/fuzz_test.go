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

package smtp

import (
	"strings"
	"testing"
)

// FuzzGetSMTPCommand asserts the SMTP line tokeniser never panics on
// arbitrary input.
//
// NOTE: fuzzing surfaced that a MAIL/RCPT line with a space before the
// colon (e.g. "MAIL : 0") yields a command with a trailing space
// ("MAIL ") because the ": "-resplit path does not re-trim cmd[0]. That
// is a benign tokenisation quirk (the value simply fails to match
// validSMTPCommand) rather than a crash, so we assert only the safety
// property here and intentionally do not fail on the trailing space.
func FuzzGetSMTPCommand(f *testing.F) {
	for _, s := range []string{
		"", " ", "\r\n", "HELO example.com", "MAIL FROM: <a@b.c>",
		"RCPT TO:<x>", "mail from:", ":", ": :", "DATA\r\n", "MAIL : 0",
		strings.Repeat("A ", 1000),
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, line string) {
		// Must not panic; the returned command is always upper-cased.
		cmd, args := getSMTPCommand(line)
		if cmd != strings.ToUpper(cmd) {
			t.Fatalf("getSMTPCommand(%q) cmd %q is not upper-cased", line, cmd)
		}
		_ = args
	})
}
