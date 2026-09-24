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

package ssh

import "testing"

func TestCanDecodeSSH(t *testing.T) {
	for _, tt := range []struct {
		name           string
		client, server []byte
		accept         bool
	}{
		{
			"server identification",
			[]byte("SSH-2.0-OpenSSH_9.6\r\n"),
			[]byte("SSH-2.0-OpenSSH_9.6\r\n"),
			true,
		},
		{
			// Server-driven: the reader emits a record from the server's
			// identification, so a client greeting alone is not an SSH service.
			"client only",
			[]byte("SSH-2.0-OpenSSH_9.6\r\n"),
			nil,
			false,
		},
		{
			"server only",
			nil,
			[]byte("SSH-2.0-OpenSSH_9.6\r\n"),
			true,
		},
		{
			// RFC 4253 4.2 lets a server send other lines first.
			"identification after a banner line",
			nil,
			[]byte("Authorized use only\r\nSSH-2.0-OpenSSH_9.6\r\n"),
			true,
		},
		{"protocol 1.99", nil, []byte("SSH-1.99-OpenSSH_3.9\r\n"), true},
		{"empty", nil, nil, false},
		{"bare letters", nil, []byte("SSH"), false},
		{"no version digit", nil, []byte("SSH-abc\r\n"), false},
		{"version but no software field", nil, []byte("SSH-2.0 archive\r\n"), false},
		{"not at a line start", nil, []byte("see SSH-2.0 for details\r\n"), false},
		{"http mentioning ssh", nil, []byte("HTTP/1.1 200 OK\r\n\r\nDownload SSH-2.0 here\r\n"), false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := Decoder.CanDecode(tt.client, tt.server); got != tt.accept {
				t.Errorf("CanDecode = %v, want %v", got, tt.accept)
			}
		})
	}
}

// The check used to be an unanchored three-byte substring over a whole
// direction. SSH is second in the port-independent scan, so any payload able
// to contain those letters was claimed before nearly every other decoder.
func TestUnanchoredMentionIsNotSSH(t *testing.T) {
	for _, data := range [][]byte{
		[]byte("GET /downloads/SSH-2.0.tar.gz HTTP/1.1\r\nHost: example.com\r\n\r\n"),
		[]byte("220 mail.example.com ESMTP ready, SSH also available\r\n"),
		append([]byte{0x00, 0xFF, 0x7F}, []byte("SSH")...),
		// An HTTP body whose line happens to begin with the prefix. RFC 4253
		// requires a second hyphen before the software version.
		[]byte("HTTP/1.1 200 OK\r\n\r\nSSH-2.0 archive contents\r\n"),
	} {
		if Decoder.CanDecode(nil, data) {
			t.Errorf("claimed %q as SSH", string(data[:min(len(data), 40)]))
		}
	}
}
