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

package opcua

import (
	"go.uber.org/zap"

	"github.com/dreadl0ck/netcap/decoder"
	decoderconfig "github.com/dreadl0ck/netcap/decoder/config"
	"github.com/dreadl0ck/netcap/decoder/core"
	logging "github.com/dreadl0ck/netcap/internal/logger"
	"github.com/dreadl0ck/netcap/types"
)

var opcuaLog = zap.NewNop()

const serviceOPCUA = "OPCUA"

// OPC UA message type signatures (3 ASCII characters)
const (
	msgTypeHello        = "HEL" // Hello message (client -> server)
	msgTypeAcknowledge  = "ACK" // Acknowledge message (server -> client)
	msgTypeError        = "ERR" // Error message
	msgTypeReverseHello = "RHE" // Reverse Hello (server -> client for reverse connect)
	msgTypeOpenChannel  = "OPN" // OpenSecureChannel
	msgTypeCloseChannel = "CLO" // CloseSecureChannel
	msgTypeMessage      = "MSG" // Service message (secured)
)

// Chunk types
const (
	chunkIntermediate = 'C' // Intermediate chunk
	chunkFinal        = 'F' // Final chunk
	chunkAbort        = 'A' // Abort
)

// Minimum header size for OPC UA Binary Protocol
const minHeaderSize = 8 // Message type (3) + Chunk type (1) + Message size (4)

// Decoder for protocol analysis and writing audit records to disk.
var Decoder = &decoder.StreamDecoder{
	Type:        types.Type_NC_OPCUA,
	Name:        serviceOPCUA,
	Description: "OPC Unified Architecture (OPC UA) is used for ICS/SCADA machine-to-machine communication",
	PostInit: func(d *decoder.StreamDecoder) error {
		var err error
		opcuaLog, _, err = logging.InitZapLogger(
			decoderconfig.Instance.Out,
			"opcua",
			decoderconfig.Instance.Debug,
		)
		return err
	},
	CanDecode: func(client, server []byte) bool {
		// OPC UA Binary Protocol messages start with a 3-byte ASCII message type
		// followed by a 1-byte chunk type, then a 4-byte little-endian message size
		return canDecodeOPCUA(client) || canDecodeOPCUA(server)
	},
	DeInit: func(sd *decoder.StreamDecoder) error {
		return opcuaLog.Sync()
	},
	Factory: &opcuaReader{},
	Typ:     core.TCP, // OPC UA uses TCP port 4840 by default
}

// canDecodeOPCUA checks if the data looks like an OPC UA Binary Protocol message.
// OPC UA messages have a very specific header format that makes detection reliable.
func canDecodeOPCUA(data []byte) bool {
	if len(data) < minHeaderSize {
		return false
	}

	// Check for valid OPC UA message type (3 ASCII bytes)
	msgType := string(data[0:3])
	switch msgType {
	case msgTypeHello,
		msgTypeAcknowledge,
		msgTypeError,
		msgTypeReverseHello,
		msgTypeOpenChannel,
		msgTypeCloseChannel,
		msgTypeMessage:
		// Valid message type
	default:
		return false
	}

	// Check chunk type (1 byte)
	chunkType := data[3]
	switch chunkType {
	case chunkIntermediate, chunkFinal, chunkAbort:
		// Valid chunk type
	default:
		return false
	}

	// Message size (little-endian uint32)
	// Sanity check: size should be at least the header size
	size := uint32(data[4]) | uint32(data[5])<<8 | uint32(data[6])<<16 | uint32(data[7])<<24
	if size < minHeaderSize || size > 65536*16 { // Max reasonable message size (1MB)
		return false
	}

	return true
}




