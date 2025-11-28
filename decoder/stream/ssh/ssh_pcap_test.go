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

import (
	"testing"
)

// TestSSHCanDecode tests the CanDecode function with sample SSH data
func TestSSHCanDecode(t *testing.T) {
	tests := []struct {
		name     string
		client   []byte
		server   []byte
		expected bool
	}{
		{
			name:     "Valid SSH-2.0 server response",
			client:   []byte("SSH-2.0-OpenSSH_6.2\r\n"),
			server:   []byte("SSH-2.0-OpenSSH_6.6.1\r\n"),
			expected: true,
		},
		{
			name:     "Server contains SSH",
			client:   []byte{},
			server:   []byte("SSH-2.0-OpenSSH_7.4\r\n"),
			expected: true,
		},
		{
			name:     "No SSH in server",
			client:   []byte("SSH-2.0-OpenSSH_6.2\r\n"),
			server:   []byte("HTTP/1.1 200 OK\r\n"),
			expected: false,
		},
		{
			name:     "Empty buffers",
			client:   []byte{},
			server:   []byte{},
			expected: false,
		},
		{
			name:     "SSH in client but not server",
			client:   []byte("SSH-2.0-OpenSSH_6.2\r\n"),
			server:   []byte{},
			expected: false,
		},
		{
			name:     "Unidirectional SSH - Server only with protocol mismatch",
			client:   []byte{},
			server:   []byte("SSH-2.0-OpenSSH_7.4p1 Debian-10+deb9u7\r\nProtocol mismatch.\n"),
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := Decoder.CanDecodeStream(tt.client, tt.server)
			if result != tt.expected {
				t.Errorf("CanDecode() = %v, expected %v", result, tt.expected)
				t.Logf("Client data: %q", string(tt.client))
				t.Logf("Server data: %q", string(tt.server))
			}
		})
	}
}

// Note: Full PCAP file tests are located in collector/ssh_test.go to avoid import cycles
