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

package pop3

import (
	"reflect"
	"testing"
)

// TestParseMessageID covers the int32 message-id parser, including the
// error paths that the original scratchpad transcript never exercised.
func TestParseMessageID(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		want    int32
		wantErr bool
	}{
		{name: "simple", in: "2", want: 2},
		{name: "zero", in: "0", want: 0},
		{name: "max int32", in: "2147483647", want: 2147483647},
		{name: "negative", in: "-1", want: -1},
		{name: "empty is error", in: "", wantErr: true},
		{name: "non-numeric is error", in: "abc", wantErr: true},
		{name: "overflow int32 is error", in: "2147483648", wantErr: true},
		{name: "float is error", in: "1.5", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseMessageID(tt.in)
			if tt.wantErr {
				if err == nil {
					t.Errorf("parseMessageID(%q) expected error, got %d", tt.in, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseMessageID(%q) unexpected error: %v", tt.in, err)
			}
			if got != tt.want {
				t.Errorf("parseMessageID(%q) = %d, want %d", tt.in, got, tt.want)
			}
		})
	}
}

// TestParseMailboxSize covers the int64 octet-count parser.
func TestParseMailboxSize(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		want    int64
		wantErr bool
	}{
		{name: "typical", in: "320", want: 320},
		{name: "zero", in: "0", want: 0},
		{name: "large", in: "9223372036854775807", want: 9223372036854775807},
		{name: "empty is error", in: "", wantErr: true},
		{name: "non-numeric is error", in: "xyz", wantErr: true},
		{name: "overflow int64 is error", in: "9223372036854775808", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseMailboxSize(tt.in)
			if tt.wantErr {
				if err == nil {
					t.Errorf("parseMailboxSize(%q) expected error, got %d", tt.in, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseMailboxSize(%q) unexpected error: %v", tt.in, err)
			}
			if got != tt.want {
				t.Errorf("parseMailboxSize(%q) = %d, want %d", tt.in, got, tt.want)
			}
		})
	}
}

// TestValidPop3ServerCommand pins the recognised server-response tokens.
func TestValidPop3ServerCommand(t *testing.T) {
	tests := []struct {
		cmd  string
		want bool
	}{
		{".", true},
		{"+", true},
		{"+OK", true},
		{"-ERR", true},
		{"TOP", true},
		{"USER", true},
		{"UIDL", true},
		{"STLS", true},
		{"SASL", true},
		{"IMPLEMENTATION", true},

		// Not in the server-command set.
		{"", false},
		{"PASS", false},
		{"RETR", false},
		{"QUIT", false},
		{"+ok", false}, // case-sensitive
	}
	for _, tt := range tests {
		t.Run(tt.cmd, func(t *testing.T) {
			if got := validPop3ServerCommand(tt.cmd); got != tt.want {
				t.Errorf("validPop3ServerCommand(%q) = %v, want %v", tt.cmd, got, tt.want)
			}
		})
	}
}

// TestGetCommand covers the POP3 line tokeniser: whitespace/CRLF trimming
// and splitting the verb from its arguments. Unlike SMTP, POP3 does not
// upper-case or special-case MAIL/RCPT.
func TestGetCommand(t *testing.T) {
	tests := []struct {
		name     string
		line     string
		wantCmd  string
		wantArgs []string
	}{
		{
			name:     "user command",
			line:     "USER frated",
			wantCmd:  "USER",
			wantArgs: []string{"frated"},
		},
		{
			name:     "no args",
			line:     "STAT",
			wantCmd:  "STAT",
			wantArgs: []string{},
		},
		{
			name:     "trailing CRLF trimmed",
			line:     "QUIT\r\n",
			wantCmd:  "QUIT",
			wantArgs: []string{},
		},
		{
			name:     "case is preserved (no folding)",
			line:     "user mrose",
			wantCmd:  "user",
			wantArgs: []string{"mrose"},
		},
		{
			name:     "multiple args (APOP)",
			line:     "APOP mrose c4c9334bac560ecc979e58001b3e22fb",
			wantCmd:  "APOP",
			wantArgs: []string{"mrose", "c4c9334bac560ecc979e58001b3e22fb"},
		},
		{
			name:     "empty line",
			line:     "",
			wantCmd:  "",
			wantArgs: []string{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd, args := getCommand(tt.line)
			if cmd != tt.wantCmd {
				t.Errorf("getCommand(%q) cmd = %q, want %q", tt.line, cmd, tt.wantCmd)
			}
			if !reflect.DeepEqual(args, tt.wantArgs) {
				t.Errorf("getCommand(%q) args = %#v, want %#v", tt.line, args, tt.wantArgs)
			}
		})
	}
}
