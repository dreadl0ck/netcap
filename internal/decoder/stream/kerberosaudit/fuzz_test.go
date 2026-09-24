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

package kerberosaudit

import "testing"

// CanDecode reads attacker-controlled bytes and the DER walk recurses, so a
// declared length that runs past the buffer has to be rejected rather than
// indexed with. That exact bug panicked the collector suite once already.
func FuzzCanDecode(f *testing.F) {
	f.Add(udpMessage(0x6a, 64))
	f.Add(tcpMessage(0x6b, 300))
	f.Add([]byte{0x6a, 0x27, 0x00, 0x00})
	f.Add([]byte{0x6a, 0x80, 0x00, 0x00})
	f.Add([]byte{0x05, 0x64, 0x1a, 0xc4, 0x03, 0x00, 0x04, 0x00})
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		// Both sides, because each direction is tested independently.
		_ = Decoder.CanDecode(data, nil)
		_ = Decoder.CanDecode(nil, data)
		_ = Decoder.CanDecode(data, data)
	})
}
