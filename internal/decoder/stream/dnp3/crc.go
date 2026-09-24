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

package dnp3

// CRC-16/DNP per IEEE 1815 Annex E: poly 0x3D65, init 0x0000, reflected in and
// out, final xor 0xFFFF. Transmitted little-endian after the link header and
// after every data block.
//
// This is the only discriminator that makes scanning for the 0x0564 start bytes
// safe. User data is binary, so those two bytes occur inside analog values; a
// scan that does not verify the CRC reports frames that were never sent.
const crcPolyReflected = 0xA6BC // bit-reverse of 0x3D65

var crcTable = buildCRCTable()

func buildCRCTable() (table [256]uint16) {
	for i := range table {
		crc := uint16(i)

		for range 8 {
			if crc&1 != 0 {
				crc = crc>>1 ^ crcPolyReflected
			} else {
				crc >>= 1
			}
		}

		table[i] = crc
	}

	return table
}

// crc16DNP returns the check value for b.
func crc16DNP(b []byte) uint16 {
	var crc uint16
	for _, v := range b {
		crc = crc>>8 ^ crcTable[byte(crc)^v]
	}

	return ^crc
}

// crcValid reports whether b is followed by its correct little-endian CRC.
// Expects len(b)+2 bytes of readable input starting at b.
func crcValid(b, crc []byte) bool {
	if len(crc) < 2 {
		return false
	}

	return uint16(crc[0])|uint16(crc[1])<<8 == crc16DNP(b)
}
