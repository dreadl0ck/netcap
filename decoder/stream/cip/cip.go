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

package cip

import (
	"go.uber.org/zap"

	"github.com/dreadl0ck/netcap/decoder"
	decoderconfig "github.com/dreadl0ck/netcap/decoder/config"
	"github.com/dreadl0ck/netcap/decoder/core"
	logging "github.com/dreadl0ck/netcap/logger"
	"github.com/dreadl0ck/netcap/types"
)

var cipLog = zap.NewNop()

const serviceCIP = "CIP"

// CIP Service Codes
const (
	CIPServiceGetAttributeAll        = 0x01
	CIPServiceSetAttributeAll        = 0x02
	CIPServiceGetAttributeList       = 0x03
	CIPServiceSetAttributeList       = 0x04
	CIPServiceReset                  = 0x05
	CIPServiceStart                  = 0x06
	CIPServiceStop                   = 0x07
	CIPServiceCreate                 = 0x08
	CIPServiceDelete                 = 0x09
	CIPServiceMultipleServicePacket  = 0x0A
	CIPServiceApplyAttributes        = 0x0D
	CIPServiceGetAttributeSingle     = 0x0E
	CIPServiceSetAttributeSingle     = 0x10
	CIPServiceFindNextObjectInstance = 0x11
	CIPServiceRestore                = 0x15
	CIPServiceSave                   = 0x16
	CIPServiceNOP                    = 0x17
	CIPServiceGetMember              = 0x18
	CIPServiceSetMember              = 0x19
	CIPServiceInsertMember           = 0x1A
	CIPServiceRemoveMember           = 0x1B
	CIPServiceGroupSync              = 0x1C
	CIPServiceForwardClose           = 0x4E
	CIPServiceReadTag                = 0x4C
	CIPServiceWriteTag               = 0x4D
	CIPServiceUnconnectedSend        = 0x52
	CIPServiceWriteTagFragmented     = 0x53
	CIPServiceForwardOpen            = 0x54
	CIPServiceReadTagFragmented      = 0x55
	CIPServiceReadModifyWriteTag     = 0x56
)

// CIP Status Codes
const (
	CIPStatusSuccess                      = 0x00
	CIPStatusConnectionFailure            = 0x01
	CIPStatusResourceUnavailable          = 0x02
	CIPStatusInvalidParameterValue        = 0x03
	CIPStatusPathSegmentError             = 0x04
	CIPStatusPathDestinationUnknown       = 0x05
	CIPStatusPartialTransfer              = 0x06
	CIPStatusConnectionLost               = 0x07
	CIPStatusServiceNotSupported          = 0x08
	CIPStatusInvalidAttributeValue        = 0x09
	CIPStatusAttributeListError           = 0x0A
	CIPStatusAlreadyInRequestedMode       = 0x0B
	CIPStatusObjectStateConflict          = 0x0C
	CIPStatusObjectAlreadyExists          = 0x0D
	CIPStatusAttributeNotSettable         = 0x0E
	CIPStatusPrivilegeViolation           = 0x0F
	CIPStatusDeviceStateConflict          = 0x10
	CIPStatusReplyDataTooLarge            = 0x11
	CIPStatusFragmentationOfPrimitive     = 0x12
	CIPStatusNotEnoughData                = 0x13
	CIPStatusAttributeNotSupported        = 0x14
	CIPStatusTooMuchData                  = 0x15
	CIPStatusObjectDoesNotExist           = 0x16
	CIPStatusServiceFragmentation         = 0x17
	CIPStatusNoStoredAttributeData        = 0x18
	CIPStatusStoreOperationFailure        = 0x19
	CIPStatusRoutingFailure               = 0x1A
	CIPStatusRoutingFailureRequest        = 0x1B
	CIPStatusRoutingFailureResponse       = 0x1C
	CIPStatusMissingAttributeListEntry    = 0x1D
	CIPStatusInvalidAttributeValueList    = 0x1E
	CIPStatusEmbeddedServiceError         = 0x1F
	CIPStatusVendorSpecificError          = 0x20
	CIPStatusInvalidParameter             = 0x21
	CIPStatusWriteOnceValueAlreadyWritten = 0x22
	CIPStatusInvalidReplyReceived         = 0x23
	CIPStatusKeyFailureInPath             = 0x25
	CIPStatusPathSizeInvalid              = 0x26
	CIPStatusUnexpectedAttributeInList    = 0x27
	CIPStatusInvalidMemberID              = 0x28
	CIPStatusMemberNotSettable            = 0x29
)

// Decoder for protocol analysis and writing audit records to disk.
var Decoder = &decoder.StreamDecoder{
	Type:        types.Type_NC_CIP,
	Name:        serviceCIP,
	Description: "Common Industrial Protocol (CIP) is used for ICS/SCADA communications in industrial automation",
	PostInit: func(d *decoder.StreamDecoder) error {
		var err error
		cipLog, _, err = logging.InitZapLogger(
			decoderconfig.Instance.Out,
			"cip",
			decoderconfig.Instance.Debug,
		)
		return err
	},
	CanDecode: func(client, server []byte) bool {
		// CIP messages can be identified by checking for valid CIP structure
		// CIP requests: service byte (bit 7 = 0), path size, path data
		// CIP responses: service byte with bit 7 set (0x80+), reserved byte, status
		return canDecodeCIP(client) || canDecodeCIP(server)
	},
	DeInit: func(sd *decoder.StreamDecoder) error {
		return cipLog.Sync()
	},
	Factory: &cipReader{},
	Typ:     core.TCP, // CIP typically uses TCP port 44818 (EtherNet/IP) or 2222
}

// canDecodeCIP checks if the data looks like a CIP or ENIP message
// This function is intentionally strict to avoid false positives
func canDecodeCIP(data []byte) bool {
	if len(data) < 4 {
		return false
	}

	// Only check for ENIP encapsulation - this is the reliable detection method
	// Raw CIP detection is too prone to false positives since CIP doesn't have
	// a magic number or strong signature without ENIP encapsulation
	return canDecodeENIP(data)
}

// canDecodeENIP checks if the data looks like an ENIP (EtherNet/IP) message
func canDecodeENIP(data []byte) bool {
	if len(data) < 24 { // ENIP header is 24 bytes
		return false
	}

	// ENIP uses little-endian
	command := uint16(data[0]) | uint16(data[1])<<8
	length := uint16(data[2]) | uint16(data[3])<<8

	// Check for valid ENIP commands
	// Note: NOP (0x0000) is excluded to avoid false positives with all-zero data
	switch command {
	case 0x0004, // List Services
		0x0063, // List Identity
		0x0064, // List Interfaces
		0x0065, // Register Session
		0x0066, // Unregister Session
		0x006F, // SendRRData (contains CIP)
		0x0070: // SendUnitData (contains CIP)
		// Valid command
	default:
		return false
	}

	// Verify we have enough data
	totalSize := 24 + int(length)
	if len(data) < totalSize {
		return false
	}

	return true
}
