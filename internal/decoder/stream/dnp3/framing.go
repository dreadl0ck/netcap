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

// IEEE 1815 link layer framing.
const (
	startByte1 = 0x05
	startByte2 = 0x64

	// start(2) + length(1) + control(1) + destination(2) + source(2) + crc(2).
	linkHeaderLen = 10

	// LENGTH counts CONTROL, DESTINATION and SOURCE plus the user data, but not
	// the start bytes, the LENGTH octet itself or any CRC. A header-only frame
	// therefore reports 5.
	linkMinLength = 5

	blockDataLen = 16
	blockCRCLen  = 2

	// LENGTH is a single octet, so 250 user octets across 16 blocks is the
	// largest frame the protocol can express.
	maxFrameLen = linkHeaderLen + 250 + 16*blockCRCLen
)

// nameUnknown is reported for any code the standard does not assign.
const nameUnknown = "UNKNOWN"

// Broadcast destinations. A broadcast control reaches every outstation on the
// link, which is a materially different event from a unicast one.
const (
	broadcastNoConfirm       = 0xFFFD
	broadcastConfirmOptional = 0xFFFE
	broadcastConfirmRequired = 0xFFFF
	selfAddress              = 0xFFFC
)

// Link layer function codes, from the low nibble of CONTROL. The meaning
// depends on PRM: a primary frame numbers its own set, a secondary frame
// another. Only USER_DATA and UNCONFIRMED_USER_DATA carry an application PDU.
const (
	linkResetLinkStates       = 0x0
	linkResetUserProcess      = 0x1
	linkTestLinkStates        = 0x2
	linkConfirmedUserData     = 0x3
	linkUnconfirmedUserData   = 0x4
	linkRequestLinkStatus     = 0x9
	linkSecondaryACK          = 0x0
	linkSecondaryNACK         = 0x1
	linkSecondaryLinkStatus   = 0xB
	linkSecondaryNotSupported = 0xF
)

// blockCount returns the number of data blocks needed for n user octets.
func blockCount(n int) int {
	return (n + blockDataLen - 1) / blockDataLen
}

// userDataLen returns the number of user octets described by a LENGTH field,
// or -1 when LENGTH is below the protocol minimum.
func userDataLen(length byte) int {
	if int(length) < linkMinLength {
		return -1
	}

	return int(length) - linkMinLength
}

// frameLen returns the on-wire size of a frame, including the link header and
// every per-block CRC.
//
// The CRCs are the part that is easy to drop: a frame reporting LENGTH 26
// carries 21 user octets across two blocks and occupies 35 bytes, not 31.
// Advancing by the wrong amount leaves the scan inside the previous frame's
// payload, where the next 0x0564 is decoded as a frame that was never sent.
func frameLen(length byte) int {
	user := userDataLen(length)
	if user < 0 {
		return -1
	}

	return linkHeaderLen + user + blockCount(user)*blockCRCLen
}

// linkFunctionName names the low nibble of CONTROL. primary selects the
// direction's code set.
func linkFunctionName(code byte, primary bool) string {
	if primary {
		switch code {
		case linkResetLinkStates:
			return "RESET_LINK_STATES"
		case linkResetUserProcess:
			return "RESET_USER_PROCESS"
		case linkTestLinkStates:
			return "TEST_LINK_STATES"
		case linkConfirmedUserData:
			return "CONFIRMED_USER_DATA"
		case linkUnconfirmedUserData:
			return "UNCONFIRMED_USER_DATA"
		case linkRequestLinkStatus:
			return "REQUEST_LINK_STATUS"
		}

		return nameUnknown
	}

	switch code {
	case linkSecondaryACK:
		return "ACK"
	case linkSecondaryNACK:
		return "NACK"
	case linkSecondaryLinkStatus:
		return "LINK_STATUS"
	case linkSecondaryNotSupported:
		return "NOT_SUPPORTED"
	}

	return nameUnknown
}

// carriesAPDU reports whether a link function code carries an application PDU.
// Parsing the body of any other frame reads link control state as a function
// code.
func carriesAPDU(code byte, primary bool) bool {
	return primary && (code == linkConfirmedUserData || code == linkUnconfirmedUserData)
}

// extractUserData strips the per-block CRCs from a frame body and reports
// whether every block was present and passed.
//
// A failing block is not dropped silently: the caller marks the frame malformed
// so that a fuzzed or corrupt frame is evidence rather than an absence.
func extractUserData(body []byte, user int) (data []byte, ok bool) {
	if user == 0 {
		return nil, true
	}

	data = make([]byte, 0, user)
	ok = true

	for offset := 0; offset < user; {
		n := min(user-offset, blockDataLen)
		start := offset + blockCRCLen*blockCount(offset)

		if start+n+blockCRCLen > len(body) {
			return data, false
		}

		if !crcValid(body[start:start+n], body[start+n:start+n+blockCRCLen]) {
			ok = false
		}

		data = append(data, body[start:start+n]...)
		offset += n
	}

	return data, ok
}

// frameStart returns the offset of the next start byte pair at or after off,
// or -1. Used only to resynchronise after a rejected frame.
func frameStart(b []byte, off int) int {
	for i := off; i+1 < len(b); i++ {
		if b[i] == startByte1 && b[i+1] == startByte2 {
			return i
		}
	}

	return -1
}
