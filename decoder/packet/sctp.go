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

package packet

import (
	"encoding/binary"

	"github.com/gogo/protobuf/proto"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	"github.com/dreadl0ck/netcap/types"
)

// SCTP chunk types (RFC 4960)
const (
	sctpChunkData             = 0
	sctpChunkInit             = 1
	sctpChunkInitAck          = 2
	sctpChunkSack             = 3
	sctpChunkHeartbeat        = 4
	sctpChunkHeartbeatAck     = 5
	sctpChunkAbort            = 6
	sctpChunkShutdown         = 7
	sctpChunkShutdownAck      = 8
	sctpChunkError            = 9
	sctpChunkCookieEcho       = 10
	sctpChunkCookieAck        = 11
	sctpChunkShutdownComplete = 14
)

// sctpChunkTypeNames maps SCTP chunk types to human-readable names
var sctpChunkTypeNames = map[uint8]string{
	sctpChunkData:             "DATA",
	sctpChunkInit:             "INIT",
	sctpChunkInitAck:          "INIT_ACK",
	sctpChunkSack:             "SACK",
	sctpChunkHeartbeat:        "HEARTBEAT",
	sctpChunkHeartbeatAck:     "HEARTBEAT_ACK",
	sctpChunkAbort:            "ABORT",
	sctpChunkShutdown:         "SHUTDOWN",
	sctpChunkShutdownAck:      "SHUTDOWN_ACK",
	sctpChunkError:            "ERROR",
	sctpChunkCookieEcho:       "COOKIE_ECHO",
	sctpChunkCookieAck:        "COOKIE_ACK",
	sctpChunkShutdownComplete: "SHUTDOWN_COMPLETE",
}

// parseSCTPChunks parses SCTP chunks from payload and returns chunk info
func parseSCTPChunks(payload []byte) (chunkCount int32, chunkTypes []string, hasINIT, hasINITACK, hasABORT, hasSHUTDOWN bool) {
	offset := 0
	for offset+4 <= len(payload) {
		chunkType := payload[offset]
		// chunkFlags := payload[offset+1]
		chunkLen := int(binary.BigEndian.Uint16(payload[offset+2 : offset+4]))

		// Minimum chunk length is 4 bytes (header only)
		if chunkLen < 4 {
			break
		}

		chunkCount++

		// Get chunk type name
		typeName := sctpChunkTypeNames[chunkType]
		if typeName == "" {
			typeName = "UNKNOWN"
		}
		chunkTypes = append(chunkTypes, typeName)

		// Check for security-relevant chunk types
		switch chunkType {
		case sctpChunkInit:
			hasINIT = true
		case sctpChunkInitAck:
			hasINITACK = true
		case sctpChunkAbort:
			hasABORT = true
		case sctpChunkShutdown:
			hasSHUTDOWN = true
		}

		// Move to next chunk (chunks are padded to 4-byte boundary)
		paddedLen := chunkLen
		if chunkLen%4 != 0 {
			paddedLen = chunkLen + (4 - chunkLen%4)
		}
		offset += paddedLen
	}
	return
}

var sctpDecoder = newGoPacketDecoder(
	types.Type_NC_SCTP,
	layers.LayerTypeSCTP,
	"The Stream Control Transmission Protocol (SCTP) is a computer networking communications protocol which operates at the transport layer and serves a role similar to the popular protocols TCP and UDP",
	func(layer gopacket.Layer, timestamp int64) proto.Message {
		if sctp, ok := layer.(*layers.SCTP); ok {
			// Parse SCTP chunks from payload for security monitoring
			chunkCount, chunkTypes, hasINIT, hasINITACK, hasABORT, hasSHUTDOWN := parseSCTPChunks(sctp.Payload)

			// Capture payload if configured (for signaling protocol analysis)
			var payload []byte
			if conf.IncludePayloads {
				payload = sctp.Payload
			}

			return &types.SCTP{
				Timestamp:       timestamp,
				SrcPort:         int32(sctp.SrcPort),
				DstPort:         int32(sctp.DstPort),
				VerificationTag: sctp.VerificationTag,
				Checksum:        sctp.Checksum,
				// Security monitoring fields
				ChunkCount:  chunkCount,
				ChunkTypes:  chunkTypes,
				HasINIT:     hasINIT,
				HasINITACK:  hasINITACK,
				HasABORT:    hasABORT,
				HasSHUTDOWN: hasSHUTDOWN,
				// Payload data
				Payload:     payload,
				PayloadSize: int32(len(sctp.Payload)),
			}
		}

		return nil
	},
)
