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

package smtp

import (
	"reflect"
	"testing"
)

// TestValidSMTPCommand pins the set of client commands recognised by the
// reader. A regression here (e.g. a renamed constant) would silently drop
// commands from the parsed conversation.
func TestValidSMTPCommand(t *testing.T) {
	tests := []struct {
		cmd  string
		want bool
	}{
		{".", true},
		{"HELO", true},
		{"MAIL FROM", true},
		{"RCPT TO", true},
		{"DATA", true},
		{"RSET", true},
		{"VRFY", true},
		{"NOOP", true},
		{"QUIT", true},
		{"EHLO", true},
		{"AUTH LOGIN", true},
		{"STARTTLS", true},
		{"SITE", true},
		{"HELP", true},

		// validSMTPCommand is case-sensitive and matches the canonical
		// upper-case forms produced by getSMTPCommand; lower-case must miss.
		{"helo", false},
		{"mail from", false},
		{"", false},
		{"UNKNOWN", false},
		{"MAIL", false}, // bare verb without "FROM"
		{"RCPT", false},
	}

	for _, tt := range tests {
		t.Run(tt.cmd, func(t *testing.T) {
			if got := validSMTPCommand(tt.cmd); got != tt.want {
				t.Errorf("validSMTPCommand(%q) = %v, want %v", tt.cmd, got, tt.want)
			}
		})
	}
}

// TestGetSMTPCommand covers the line-tokeniser, including the special
// "MAIL FROM:"/"RCPT TO:" handling that splits on ": " and strips angle
// brackets from the address, plus whitespace/CRLF trimming and case folding.
func TestGetSMTPCommand(t *testing.T) {
	tests := []struct {
		name     string
		line     string
		wantCmd  string
		wantArgs []string
	}{
		{
			name:     "simple verb",
			line:     "HELO example.com",
			wantCmd:  "HELO",
			wantArgs: []string{"example.com"},
		},
		{
			name:     "lower case folded to upper",
			line:     "ehlo client.local",
			wantCmd:  "EHLO",
			wantArgs: []string{"client.local"},
		},
		{
			name:     "trailing CRLF trimmed",
			line:     "QUIT\r\n",
			wantCmd:  "QUIT",
			wantArgs: []string{},
		},
		{
			name:     "no args",
			line:     "DATA",
			wantCmd:  "DATA",
			wantArgs: []string{},
		},
		{
			// MAIL/RCPT lines are re-split on ": " so the command keeps the
			// full "MAIL FROM" verb and the address has its <> stripped.
			name:     "MAIL FROM strips angle brackets",
			line:     "MAIL FROM: <ned.pwned.se@gmx.com>",
			wantCmd:  "MAIL FROM",
			wantArgs: []string{"ned.pwned.se@gmx.com"},
		},
		{
			name:     "RCPT TO strips angle brackets",
			line:     "RCPT TO: <homer.pwned.se@gmx.com>",
			wantCmd:  "RCPT TO",
			wantArgs: []string{"homer.pwned.se@gmx.com"},
		},
		{
			name:     "lower case MAIL FROM still split on colon-space",
			line:     "mail from: <a@b.c>",
			wantCmd:  "MAIL FROM",
			wantArgs: []string{"a@b.c"},
		},
		{
			name:     "empty line yields empty command and no args",
			line:     "",
			wantCmd:  "",
			wantArgs: []string{},
		},
		{
			name:     "whitespace only line",
			line:     "  \r\n",
			wantCmd:  "",
			wantArgs: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd, args := getSMTPCommand(tt.line)
			if cmd != tt.wantCmd {
				t.Errorf("getSMTPCommand(%q) cmd = %q, want %q", tt.line, cmd, tt.wantCmd)
			}
			if !reflect.DeepEqual(args, tt.wantArgs) {
				t.Errorf("getSMTPCommand(%q) args = %#v, want %#v", tt.line, args, tt.wantArgs)
			}
		})
	}
}
