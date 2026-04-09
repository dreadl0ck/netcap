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

package bacnetip

import (
	"go.uber.org/zap"

	"github.com/dreadl0ck/netcap/decoder"
	decoderconfig "github.com/dreadl0ck/netcap/decoder/config"
	"github.com/dreadl0ck/netcap/decoder/core"
	logging "github.com/dreadl0ck/netcap/internal/logger"
	"github.com/dreadl0ck/netcap/types"
)

var bacnetipLog = zap.NewNop()

const serviceBACnetIP = "BACnetIP"

// BACnet/IP uses UDP port 47808 (0xBAC0) by default

// BVLC (BACnet Virtual Link Control) Type
const (
	bvlcTypeBACnetIP = 0x81 // BACnet/IP (Annex J)
)

// BVLC Function codes
const (
	BVLCResult                          = 0x00
	BVLCWriteBroadcastDistributionTable = 0x01
	BVLCReadBroadcastDistributionTable  = 0x02
	BVLCReadBroadcastDistributionTableAck = 0x03
	BVLCForwardedNPDU                   = 0x04
	BVLCRegisterForeignDevice           = 0x05
	BVLCReadForeignDeviceTable          = 0x06
	BVLCReadForeignDeviceTableAck       = 0x07
	BVLCDeleteForeignDeviceTableEntry   = 0x08
	BVLCDistributeBroadcastToNetwork    = 0x09
	BVLCOriginalUnicastNPDU             = 0x0A
	BVLCOriginalBroadcastNPDU           = 0x0B
	BVLCSecureBVLL                      = 0x0C
)

// Minimum header sizes
const (
	minBVLCHeaderSize = 4 // Type (1) + Function (1) + Length (2)
	minNPDUHeaderSize = 2 // Version (1) + Control (1)
)

// Decoder for protocol analysis and writing audit records to disk.
var Decoder = &decoder.StreamDecoder{
	Type:        types.Type_NC_BACnetIP,
	Name:        serviceBACnetIP,
	Description: "BACnet/IP (Building Automation and Control Networks over IP) for building automation systems",
	PostInit: func(d *decoder.StreamDecoder) error {
		var err error
		bacnetipLog, _, err = logging.InitZapLogger(
			decoderconfig.Instance.Out,
			"bacnetip",
			decoderconfig.Instance.Debug,
		)
		return err
	},
	CanDecode: func(client, server []byte) bool {
		// BACnet/IP runs over UDP, check both directions
		return canDecodeBACnetIP(client) || canDecodeBACnetIP(server)
	},
	DeInit: func(sd *decoder.StreamDecoder) error {
		return bacnetipLog.Sync()
	},
	Factory: &bacnetipReader{},
	Typ:     core.UDP, // BACnet/IP uses UDP port 47808
}

// canDecodeBACnetIP checks if the data looks like a BACnet/IP message.
// BACnet/IP messages have a specific BVLC header format.
func canDecodeBACnetIP(data []byte) bool {
	if len(data) < minBVLCHeaderSize {
		return false
	}

	// Check BVLC Type (first byte must be 0x81 for BACnet/IP)
	if data[0] != bvlcTypeBACnetIP {
		return false
	}

	// Check BVLC Function code
	funcCode := data[1]
	if !isValidBVLCFunction(funcCode) {
		return false
	}

	// Check BVLC Length (bytes 2-3, big-endian)
	length := uint16(data[2])<<8 | uint16(data[3])

	// Sanity checks on length
	// Length must be at least the header size
	// Length should be reasonable (max ~1500 for typical Ethernet)
	if length < minBVLCHeaderSize || length > 1500 {
		return false
	}

	return true
}

// isValidBVLCFunction checks if the function code is a valid BVLC function.
func isValidBVLCFunction(code uint8) bool {
	switch code {
	case BVLCResult,
		BVLCWriteBroadcastDistributionTable,
		BVLCReadBroadcastDistributionTable,
		BVLCReadBroadcastDistributionTableAck,
		BVLCForwardedNPDU,
		BVLCRegisterForeignDevice,
		BVLCReadForeignDeviceTable,
		BVLCReadForeignDeviceTableAck,
		BVLCDeleteForeignDeviceTableEntry,
		BVLCDistributeBroadcastToNetwork,
		BVLCOriginalUnicastNPDU,
		BVLCOriginalBroadcastNPDU,
		BVLCSecureBVLL:
		return true
	}
	return false
}

// GetBVLCFunctionName returns the human-readable name for a BVLC function code.
func GetBVLCFunctionName(code uint8) string {
	switch code {
	case BVLCResult:
		return "BVLC-Result"
	case BVLCWriteBroadcastDistributionTable:
		return "Write-Broadcast-Distribution-Table"
	case BVLCReadBroadcastDistributionTable:
		return "Read-Broadcast-Distribution-Table"
	case BVLCReadBroadcastDistributionTableAck:
		return "Read-Broadcast-Distribution-Table-Ack"
	case BVLCForwardedNPDU:
		return "Forwarded-NPDU"
	case BVLCRegisterForeignDevice:
		return "Register-Foreign-Device"
	case BVLCReadForeignDeviceTable:
		return "Read-Foreign-Device-Table"
	case BVLCReadForeignDeviceTableAck:
		return "Read-Foreign-Device-Table-Ack"
	case BVLCDeleteForeignDeviceTableEntry:
		return "Delete-Foreign-Device-Table-Entry"
	case BVLCDistributeBroadcastToNetwork:
		return "Distribute-Broadcast-To-Network"
	case BVLCOriginalUnicastNPDU:
		return "Original-Unicast-NPDU"
	case BVLCOriginalBroadcastNPDU:
		return "Original-Broadcast-NPDU"
	case BVLCSecureBVLL:
		return "Secure-BVLL"
	default:
		return "Unknown"
	}
}

