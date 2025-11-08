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
