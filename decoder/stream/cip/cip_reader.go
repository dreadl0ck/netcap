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

package cip

import (
	"bytes"
	"encoding/binary"
	"sync/atomic"

	"go.uber.org/zap"

	"github.com/dreadl0ck/netcap/decoder/core"
	"github.com/dreadl0ck/netcap/types"
)

// ENIP (EtherNet/IP) Header size
const enipHeaderSize = 24

// ENIP Command codes
const (
	ENIPCommandNOP               = 0x0000
	ENIPCommandListServices      = 0x0004
	ENIPCommandListIdentity      = 0x0063
	ENIPCommandListInterfaces    = 0x0064
	ENIPCommandRegisterSession   = 0x0065
	ENIPCommandUnregisterSession = 0x0066
	ENIPCommandSendRRData        = 0x006F
	ENIPCommandSendUnitData      = 0x0070
)

// Common Packet Format item type IDs
const (
	CPFItemIDNullAddress       = 0x0000
	CPFItemIDConnectedAddress  = 0x00A1
	CPFItemIDSequencedAddress  = 0x8002
	CPFItemIDUnconnectedData   = 0x00B2
	CPFItemIDConnectedData     = 0x00B1
	CPFItemIDSocketAddrInfoO2T = 0x8000
	CPFItemIDSocketAddrInfoT2O = 0x8001
)

// CIP Path Segment Types
const (
	CIPPathSegmentPortSegment     = 0x00
	CIPPathSegmentLogicalSegment  = 0x20
	CIPPathSegmentNetworkSegment  = 0x40
	CIPPathSegmentSymbolicSegment = 0x60
	CIPPathSegmentDataSegment     = 0x80
	CIPPathSegmentDataTypeConstr  = 0xA0
	CIPPathSegmentDataTypeElement = 0xC0
	CIPPathSegmentReserved        = 0xE0
)

// Logical Segment Type bits
const (
	CIPLogicalSegmentClassID         = 0x00
	CIPLogicalSegmentInstanceID      = 0x04
	CIPLogicalSegmentMemberID        = 0x08
	CIPLogicalSegmentConnectionPoint = 0x0C
	CIPLogicalSegmentAttributeID     = 0x10
	CIPLogicalSegmentSpecial         = 0x14
	CIPLogicalSegmentServiceID       = 0x18
)

type cipReader struct {
	conversation *core.ConversationInfo
}

// New returns a new CIP reader.
func (c *cipReader) New(conversation *core.ConversationInfo) core.StreamDecoderInterface {
	return &cipReader{
		conversation: conversation,
	}
}

// Decode parses CIP messages from the stream.
// CIP is typically encapsulated in ENIP (EtherNet/IP) on TCP port 44818.
// This decoder ONLY handles ENIP-encapsulated CIP to avoid false positives.
// Raw CIP (without ENIP) is not parsed because it lacks a strong signature.
func (c *cipReader) Decode() {
	if Decoder.Writer == nil {
		cipLog.Error("CIP Decoder.Writer is nil")
		return
	}

	var buf bytes.Buffer

	for _, d := range c.conversation.Data {
		buf.Write(d.Raw())
	}

	data := buf.Bytes()
	offset := 0

	for offset < len(data)-enipHeaderSize {
		// Only parse ENIP-encapsulated CIP (has strong signature)
		if c.isENIPHeader(data[offset:]) {
			consumed := c.parseENIPMessage(data[offset:])
			if consumed > 0 {
				offset += consumed
				continue
			}
		}

		// Skip byte and try again - don't fall back to raw CIP parsing
		// as it causes too many false positives
		offset++
	}
}

// writeCIPRecord writes a CIP record with connection info
func (c *cipReader) writeCIPRecord(msg *types.CIP) {
	msg.SrcIP = c.conversation.ClientIP
	msg.DstIP = c.conversation.ServerIP
	msg.SrcPort = int32(c.conversation.ClientPort)
	msg.DstPort = int32(c.conversation.ServerPort)

	err := Decoder.Writer.Write(msg)
	if err != nil {
		cipLog.Error("failed to write CIP record", zap.Error(err))
	} else {
		atomic.AddInt64(&Decoder.NumRecordsWritten, 1)
	}
}

// isENIPHeader checks if data starts with a valid ENIP header
func (c *cipReader) isENIPHeader(data []byte) bool {
	if len(data) < enipHeaderSize {
		return false
	}

	// ENIP header format (little-endian):
	// Bytes 0-1: Command (valid commands are 0x0000-0x0070)
	// Bytes 2-3: Length of data following header
	// Bytes 4-7: Session handle
	// Bytes 8-11: Status (0 = success)
	// Bytes 12-19: Sender context
	// Bytes 20-23: Options (typically 0)

	command := binary.LittleEndian.Uint16(data[0:2])
	length := binary.LittleEndian.Uint16(data[2:4])

	// Validate command is a known ENIP command
	switch command {
	case ENIPCommandNOP,
		ENIPCommandListServices,
		ENIPCommandListIdentity,
		ENIPCommandListInterfaces,
		ENIPCommandRegisterSession,
		ENIPCommandUnregisterSession,
		ENIPCommandSendRRData,
		ENIPCommandSendUnitData:
		// Valid command
	default:
		return false
	}

	// Check that we have enough data for the header + payload
	totalSize := enipHeaderSize + int(length)
	if len(data) < totalSize {
		return false
	}

	return true
}

// parseENIPMessage parses an ENIP message and extracts CIP payloads
func (c *cipReader) parseENIPMessage(data []byte) int {
	if len(data) < enipHeaderSize {
		return 0
	}

	command := binary.LittleEndian.Uint16(data[0:2])
	length := binary.LittleEndian.Uint16(data[2:4])

	totalSize := enipHeaderSize + int(length)
	if len(data) < totalSize {
		return 0
	}

	// Only SendRRData and SendUnitData contain CIP messages
	if command != ENIPCommandSendRRData && command != ENIPCommandSendUnitData {
		return totalSize
	}

	// Parse Common Packet Format (CPF) to extract CIP data
	cpfData := data[enipHeaderSize:totalSize]
	c.parseCPF(cpfData)

	return totalSize
}

// parseCPF parses Common Packet Format and extracts CIP messages
func (c *cipReader) parseCPF(data []byte) {
	if len(data) < 6 {
		return
	}

	// CPF format:
	// Bytes 0-3: Interface handle (for SendRRData) or connection ID (for SendUnitData)
	// Bytes 4-5: Timeout (for SendRRData only)
	// Following: Item count and items

	// Skip interface handle and timeout
	offset := 0

	// For SendRRData, skip interface handle (4 bytes) and timeout (2 bytes)
	// The CPF items follow
	if len(data) > 6 {
		offset = 6
	}

	if offset+2 > len(data) {
		return
	}

	itemCount := binary.LittleEndian.Uint16(data[offset : offset+2])
	offset += 2

	// Parse each CPF item
	for i := uint16(0); i < itemCount && offset+4 <= len(data); i++ {
		itemTypeID := binary.LittleEndian.Uint16(data[offset : offset+2])
		itemLength := binary.LittleEndian.Uint16(data[offset+2 : offset+4])
		offset += 4

		if offset+int(itemLength) > len(data) {
			break
		}

		itemData := data[offset : offset+int(itemLength)]

		// Extract CIP data from Unconnected Data or Connected Data items
		if itemTypeID == CPFItemIDUnconnectedData {
			c.parseCIPData(itemData)
		} else if itemTypeID == CPFItemIDConnectedData {
			// Connected Data items have a 2-byte sequence count at the start
			if len(itemData) > 2 {
				cipData := itemData[2:] // Skip sequence count
				c.parseCIPData(cipData)
			}
		}

		offset += int(itemLength)
	}
}

// parseCIPData parses CIP data which may contain a single message or Multiple Service Packet
func (c *cipReader) parseCIPData(data []byte) {
	if len(data) < 2 {
		return
	}

	service := data[0] & 0x7F // Mask off response bit

	// Check for Multiple Service Packet (0x0A)
	if service == CIPServiceMultipleServicePacket {
		c.parseMultipleServicePacket(data)
		return
	}

	// Parse as single CIP message
	msg, _ := c.parseCIPMessage(data)
	if msg != nil {
		c.writeCIPRecord(msg)
	}
}

// parseMultipleServicePacket parses a CIP Multiple Service Packet which contains
// multiple CIP requests/responses
func (c *cipReader) parseMultipleServicePacket(data []byte) {
	if len(data) < 6 {
		return
	}

	isResponse := (data[0] & 0x80) != 0
	// service := data[0] & 0x7F // 0x0A
	pathSizeWords := int(data[1])
	pathSizeBytes := pathSizeWords * 2
	headerSize := 2 + pathSizeBytes

	if len(data) < headerSize+2 {
		return
	}

	// For responses, there's a reserved byte, status, and additional status size
	dataOffset := headerSize
	if isResponse {
		// Response format: service (1) + reserved (1) + status (1) + add_status_size (1)
		dataOffset = 4
		if len(data) < dataOffset+2 {
			return
		}
		// Skip additional status if present
		addStatusSize := int(data[3]) * 2
		dataOffset += addStatusSize
	}

	if dataOffset+2 > len(data) {
		return
	}

	// Number of services
	serviceCount := binary.LittleEndian.Uint16(data[dataOffset : dataOffset+2])
	dataOffset += 2

	if serviceCount == 0 || serviceCount > 100 { // Sanity check
		return
	}

	// Offset list (2 bytes per service)
	offsetListSize := int(serviceCount) * 2
	if dataOffset+offsetListSize > len(data) {
		return
	}

	offsets := make([]uint16, serviceCount)
	for i := uint16(0); i < serviceCount; i++ {
		offsets[i] = binary.LittleEndian.Uint16(data[dataOffset+int(i)*2 : dataOffset+int(i)*2+2])
	}
	dataOffset += offsetListSize

	// The offsets are relative to the start of the service data (after the offset list)
	// Actually, they're relative to the number of services field
	baseOffset := headerSize
	if isResponse {
		baseOffset = 4 + int(data[3])*2 // After response header
	}

	// Parse each embedded service
	for i := uint16(0); i < serviceCount; i++ {
		serviceOffset := baseOffset + int(offsets[i])
		if serviceOffset >= len(data) {
			continue
		}

		// Determine the length of this service data
		var serviceLen int
		if i < serviceCount-1 {
			serviceLen = int(offsets[i+1]) - int(offsets[i])
		} else {
			serviceLen = len(data) - serviceOffset
		}

		if serviceLen <= 0 || serviceOffset+serviceLen > len(data) {
			continue
		}

		serviceData := data[serviceOffset : serviceOffset+serviceLen]
		msg, _ := c.parseCIPMessage(serviceData)
		if msg != nil {
			c.writeCIPRecord(msg)
		}
	}
}

// parseCIPMessage parses a single CIP message from the data.
// Returns the parsed message and the number of bytes consumed.
func (c *cipReader) parseCIPMessage(data []byte) (*types.CIP, int) {
	if len(data) < 4 {
		return nil, 0
	}

	service := data[0]
	isResponse := (service & 0x80) != 0

	if isResponse {
		return c.parseCIPResponse(data)
	}
	return c.parseCIPRequest(data)
}

// parseCIPRequest parses a CIP request message.
// Request format:
// - Byte 0: Service (bit 7 = 0 for request)
// - Byte 1: Path size in words (2 bytes per word)
// - Bytes 2+: EPATH (padded path)
// - Remaining: Service-specific data
//
// When encapsulated in ENIP, we know the total message length and can extract the data.
func (c *cipReader) parseCIPRequest(data []byte) (*types.CIP, int) {
	if len(data) < 2 {
		return nil, 0
	}

	service := data[0]
	pathSizeWords := int(data[1])

	// Validate service code (must not have bit 7 set)
	if service&0x80 != 0 {
		return nil, 0
	}

	// Validate path size (0 is valid for some services, max is 127)
	if pathSizeWords > 127 {
		return nil, 0
	}

	pathSizeBytes := pathSizeWords * 2
	headerSize := 2 + pathSizeBytes

	if len(data) < headerSize {
		return nil, 0
	}

	msg := &types.CIP{
		Response:  false,
		ServiceID: int32(service),
	}

	// Set timestamp if conversation context is available
	if c.conversation != nil {
		msg.Timestamp = c.conversation.FirstClientPacket.UnixNano()
	}

	// Parse EPATH to extract Class ID and Instance ID
	if pathSizeBytes > 0 {
		pathData := data[2 : 2+pathSizeBytes]
		classID, instanceID := c.parseEPATH(pathData)
		msg.ClassID = classID
		msg.InstanceID = instanceID
	}

	// Extract service-specific data (everything after the path)
	// When called from ENIP parsing, data is the complete CIP message
	if len(data) > headerSize {
		msg.Data = data[headerSize:]
	}

	// Return the full message length (entire data slice)
	return msg, len(data)
}

// parseCIPResponse parses a CIP response message.
// Response format:
// - Byte 0: Service (bit 7 = 1 for response, bits 0-6 = original service)
// - Byte 1: Reserved (0x00)
// - Byte 2: General Status
// - Byte 3: Size of additional status (in words)
// - Bytes 4+: Additional status (if any)
// - Remaining: Response data
//
// When encapsulated in ENIP, we know the total message length and can extract the data.
func (c *cipReader) parseCIPResponse(data []byte) (*types.CIP, int) {
	if len(data) < 4 {
		return nil, 0
	}

	service := data[0]
	reserved := data[1]
	status := data[2]
	additionalStatusSize := int(data[3])

	// Validate response format
	if service&0x80 == 0 {
		return nil, 0
	}

	// Reserved byte should be 0
	if reserved != 0 {
		// Some implementations may not follow spec strictly
		cipLog.Debug("CIP response reserved byte is not zero",
			zap.Uint8("reserved", reserved))
	}

	// Validate additional status size (sanity check)
	if additionalStatusSize > 64 {
		return nil, 0
	}

	// Calculate header size (fixed header + additional status)
	additionalStatusBytes := additionalStatusSize * 2
	headerSize := 4 + additionalStatusBytes

	if len(data) < headerSize {
		return nil, 0
	}

	msg := &types.CIP{
		Response:  true,
		ServiceID: int32(service & 0x7F), // Original service code without response bit
		Status:    int32(status),
	}

	// Set timestamp if conversation context is available
	if c.conversation != nil {
		msg.Timestamp = c.conversation.FirstClientPacket.UnixNano()
	}

	// Parse additional status words
	if additionalStatusSize > 0 {
		additionalStatus := make([]uint32, 0, additionalStatusSize)
		for i := 0; i < additionalStatusSize; i++ {
			offset := 4 + i*2
			if offset+2 <= len(data) {
				statusWord := binary.LittleEndian.Uint16(data[offset : offset+2])
				additionalStatus = append(additionalStatus, uint32(statusWord))
			}
		}
		msg.AdditionalStatus = additionalStatus
	}

	// Extract response data (everything after the header)
	// When called from ENIP parsing, data is the complete CIP message
	if len(data) > headerSize {
		msg.Data = data[headerSize:]
	}

	// Return the full message length (entire data slice)
	return msg, len(data)
}

// parseEPATH parses a CIP EPATH (padded path) to extract Class ID and Instance ID.
// EPATH format:
// Each segment starts with a segment type byte followed by segment-specific data.
// Logical segments (most common) have format:
// - Segment type: 0x20 = Class ID, 0x24 = Instance ID, etc.
// - Format bits determine size: 8-bit, 16-bit, or 32-bit value follows
func (c *cipReader) parseEPATH(data []byte) (classID uint32, instanceID uint32) {
	offset := 0

	for offset < len(data) {
		if offset >= len(data) {
			break
		}

		segmentType := data[offset]
		segmentTypeClass := segmentType & 0xE0 // Top 3 bits determine segment class

		switch segmentTypeClass {
		case CIPPathSegmentLogicalSegment:
			// Logical segment
			logicalType := segmentType & 0x1C // Bits 2-4 determine logical type
			formatBits := segmentType & 0x03  // Bottom 2 bits determine format

			offset++
			if offset >= len(data) {
				return
			}

			var value uint32
			switch formatBits {
			case 0: // 8-bit value
				value = uint32(data[offset])
				offset++
			case 1: // 16-bit value (with padding)
				offset++ // Skip padding byte
				if offset+2 > len(data) {
					return
				}
				value = uint32(binary.LittleEndian.Uint16(data[offset : offset+2]))
				offset += 2
			case 2: // 32-bit value (with padding)
				offset++ // Skip padding byte
				if offset+4 > len(data) {
					return
				}
				value = binary.LittleEndian.Uint32(data[offset : offset+4])
				offset += 4
			default:
				offset++
			}

			switch logicalType {
			case CIPLogicalSegmentClassID:
				classID = value
			case CIPLogicalSegmentInstanceID:
				instanceID = value
			}

		case CIPPathSegmentPortSegment:
			// Port segment: skip based on extended link address flag
			if segmentType&0x10 != 0 {
				// Extended link address
				offset++
				if offset >= len(data) {
					return
				}
				linkAddrSize := int(data[offset])
				offset += 1 + linkAddrSize
				// Pad to word boundary
				if linkAddrSize%2 != 0 {
					offset++
				}
			} else {
				// Simple port segment
				offset += 2
			}

		case CIPPathSegmentDataSegment:
			// Data segment: skip based on format
			offset++
			if offset >= len(data) {
				return
			}
			dataSize := int(data[offset]) * 2 // Size in words
			offset += 1 + dataSize

		case CIPPathSegmentSymbolicSegment:
			// Symbolic segment
			offset++
			if offset >= len(data) {
				return
			}
			symbolSize := int(data[offset])
			offset += 1 + symbolSize
			// Pad to word boundary
			if symbolSize%2 != 0 {
				offset++
			}

		default:
			// Skip unknown segment types
			offset++
		}
	}

	return
}

// GetServiceName returns the human-readable name for a CIP service code.
func GetServiceName(service uint8) string {
	switch service {
	case CIPServiceGetAttributeAll:
		return "Get_Attribute_All"
	case CIPServiceSetAttributeAll:
		return "Set_Attribute_All"
	case CIPServiceGetAttributeList:
		return "Get_Attribute_List"
	case CIPServiceSetAttributeList:
		return "Set_Attribute_List"
	case CIPServiceReset:
		return "Reset"
	case CIPServiceStart:
		return "Start"
	case CIPServiceStop:
		return "Stop"
	case CIPServiceCreate:
		return "Create"
	case CIPServiceDelete:
		return "Delete"
	case CIPServiceMultipleServicePacket:
		return "Multiple_Service_Packet"
	case CIPServiceApplyAttributes:
		return "Apply_Attributes"
	case CIPServiceGetAttributeSingle:
		return "Get_Attribute_Single"
	case CIPServiceSetAttributeSingle:
		return "Set_Attribute_Single"
	case CIPServiceFindNextObjectInstance:
		return "Find_Next_Object_Instance"
	case CIPServiceRestore:
		return "Restore"
	case CIPServiceSave:
		return "Save"
	case CIPServiceNOP:
		return "NOP"
	case CIPServiceGetMember:
		return "Get_Member"
	case CIPServiceSetMember:
		return "Set_Member"
	case CIPServiceInsertMember:
		return "Insert_Member"
	case CIPServiceRemoveMember:
		return "Remove_Member"
	case CIPServiceGroupSync:
		return "Group_Sync"
	case CIPServiceForwardClose:
		return "Forward_Close"
	case CIPServiceReadTag:
		return "Read_Tag"
	case CIPServiceWriteTag:
		return "Write_Tag"
	case CIPServiceUnconnectedSend:
		return "Unconnected_Send"
	case CIPServiceWriteTagFragmented:
		return "Write_Tag_Fragmented"
	case CIPServiceForwardOpen:
		return "Forward_Open"
	case CIPServiceReadTagFragmented:
		return "Read_Tag_Fragmented"
	case CIPServiceReadModifyWriteTag:
		return "Read_Modify_Write_Tag"
	default:
		return "Unknown"
	}
}

// GetStatusName returns the human-readable name for a CIP status code.
func GetStatusName(status uint8) string {
	switch status {
	case CIPStatusSuccess:
		return "Success"
	case CIPStatusConnectionFailure:
		return "Connection_Failure"
	case CIPStatusResourceUnavailable:
		return "Resource_Unavailable"
	case CIPStatusInvalidParameterValue:
		return "Invalid_Parameter_Value"
	case CIPStatusPathSegmentError:
		return "Path_Segment_Error"
	case CIPStatusPathDestinationUnknown:
		return "Path_Destination_Unknown"
	case CIPStatusPartialTransfer:
		return "Partial_Transfer"
	case CIPStatusConnectionLost:
		return "Connection_Lost"
	case CIPStatusServiceNotSupported:
		return "Service_Not_Supported"
	case CIPStatusInvalidAttributeValue:
		return "Invalid_Attribute_Value"
	case CIPStatusAttributeListError:
		return "Attribute_List_Error"
	case CIPStatusAlreadyInRequestedMode:
		return "Already_In_Requested_Mode"
	case CIPStatusObjectStateConflict:
		return "Object_State_Conflict"
	case CIPStatusObjectAlreadyExists:
		return "Object_Already_Exists"
	case CIPStatusAttributeNotSettable:
		return "Attribute_Not_Settable"
	case CIPStatusPrivilegeViolation:
		return "Privilege_Violation"
	case CIPStatusDeviceStateConflict:
		return "Device_State_Conflict"
	case CIPStatusReplyDataTooLarge:
		return "Reply_Data_Too_Large"
	case CIPStatusFragmentationOfPrimitive:
		return "Fragmentation_Of_Primitive_Value"
	case CIPStatusNotEnoughData:
		return "Not_Enough_Data"
	case CIPStatusAttributeNotSupported:
		return "Attribute_Not_Supported"
	case CIPStatusTooMuchData:
		return "Too_Much_Data"
	case CIPStatusObjectDoesNotExist:
		return "Object_Does_Not_Exist"
	case CIPStatusServiceFragmentation:
		return "Service_Fragmentation_Sequence_Not_In_Progress"
	case CIPStatusNoStoredAttributeData:
		return "No_Stored_Attribute_Data"
	case CIPStatusStoreOperationFailure:
		return "Store_Operation_Failure"
	case CIPStatusRoutingFailure:
		return "Routing_Failure"
	case CIPStatusRoutingFailureRequest:
		return "Routing_Failure_Request_Too_Large"
	case CIPStatusRoutingFailureResponse:
		return "Routing_Failure_Response_Too_Large"
	case CIPStatusMissingAttributeListEntry:
		return "Missing_Attribute_List_Entry"
	case CIPStatusInvalidAttributeValueList:
		return "Invalid_Attribute_Value_List"
	case CIPStatusEmbeddedServiceError:
		return "Embedded_Service_Error"
	case CIPStatusVendorSpecificError:
		return "Vendor_Specific_Error"
	case CIPStatusInvalidParameter:
		return "Invalid_Parameter"
	case CIPStatusWriteOnceValueAlreadyWritten:
		return "Write_Once_Value_Already_Written"
	case CIPStatusInvalidReplyReceived:
		return "Invalid_Reply_Received"
	case CIPStatusKeyFailureInPath:
		return "Key_Failure_In_Path"
	case CIPStatusPathSizeInvalid:
		return "Path_Size_Invalid"
	case CIPStatusUnexpectedAttributeInList:
		return "Unexpected_Attribute_In_List"
	case CIPStatusInvalidMemberID:
		return "Invalid_Member_ID"
	case CIPStatusMemberNotSettable:
		return "Member_Not_Settable"
	default:
		return "Unknown"
	}
}
