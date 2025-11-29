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
	"encoding/hex"
	"sync/atomic"

	"go.uber.org/zap"

	decoderconfig "github.com/dreadl0ck/netcap/decoder/config"
	"github.com/dreadl0ck/netcap/decoder/core"
	"github.com/dreadl0ck/netcap/types"
)

// APDU Types (Application Protocol Data Unit)
const (
	APDUConfirmedRequest   = 0
	APDUUnconfirmedRequest = 1
	APDUSimpleAck          = 2
	APDUComplexAck         = 3
	APDUSegmentAck         = 4
	APDUError              = 5
	APDUReject             = 6
	APDUAbort              = 7
)

// Confirmed Service Choices
const (
	// Alarm and Event Services
	ServiceAcknowledgeAlarm    = 0
	ServiceConfirmedCOVNotification = 1
	ServiceConfirmedEventNotification = 2
	ServiceGetAlarmSummary     = 3
	ServiceGetEnrollmentSummary = 4
	ServiceSubscribeCOV        = 5
	ServiceSubscribeCOVProperty = 28
	ServiceLifeSafetyOperation = 27

	// File Services
	ServiceAtomicReadFile  = 6
	ServiceAtomicWriteFile = 7

	// Object Access Services
	ServiceAddListElement      = 8
	ServiceRemoveListElement   = 9
	ServiceCreateObject        = 10
	ServiceDeleteObject        = 11
	ServiceReadProperty        = 12
	ServiceReadPropertyConditional = 13
	ServiceReadPropertyMultiple = 14
	ServiceReadRange           = 26
	ServiceWriteProperty       = 15
	ServiceWritePropertyMultiple = 16

	// Remote Device Management Services
	ServiceDeviceCommunicationControl = 17
	ServiceConfirmedPrivateTransfer  = 18
	ServiceConfirmedTextMessage      = 19
	ServiceReinitializeDevice        = 20

	// Virtual Terminal Services
	ServiceVTOpen  = 21
	ServiceVTClose = 22
	ServiceVTData  = 23
)

// Unconfirmed Service Choices
const (
	ServiceIAm                    = 0
	ServiceIHave                  = 1
	ServiceUnconfirmedCOVNotification = 2
	ServiceUnconfirmedEventNotification = 3
	ServiceUnconfirmedPrivateTransfer = 4
	ServiceUnconfirmedTextMessage = 5
	ServiceTimeSynchronization    = 6
	ServiceWhoHas                 = 7
	ServiceWhoIs                  = 8
	ServiceUTCTimeSynchronization = 9
	ServiceWriteGroup             = 10
	ServiceUnconfirmedCOVNotificationMultiple = 11
)

// Network Layer Message Types
const (
	NetworkWhoIsRouterToNetwork    = 0x00
	NetworkIAmRouterToNetwork      = 0x01
	NetworkICouldBeRouterToNetwork = 0x02
	NetworkRejectMessageToNetwork  = 0x03
	NetworkRouterBusyToNetwork     = 0x04
	NetworkRouterAvailableToNetwork = 0x05
	NetworkInitRouteTable          = 0x06
	NetworkInitRouteTableAck       = 0x07
	NetworkEstablishConnectionToNetwork = 0x08
	NetworkDisconnectConnectionToNetwork = 0x09
	NetworkWhatIsNetworkNumber     = 0x12
	NetworkNetworkNumberIs         = 0x13
)

// Object Types
const (
	ObjectAnalogInput        = 0
	ObjectAnalogOutput       = 1
	ObjectAnalogValue        = 2
	ObjectBinaryInput        = 3
	ObjectBinaryOutput       = 4
	ObjectBinaryValue        = 5
	ObjectCalendar           = 6
	ObjectCommand            = 7
	ObjectDevice             = 8
	ObjectEventEnrollment    = 9
	ObjectFile               = 10
	ObjectGroup              = 11
	ObjectLoop               = 12
	ObjectMultiStateInput    = 13
	ObjectMultiStateOutput   = 14
	ObjectNotificationClass  = 15
	ObjectProgram            = 16
	ObjectSchedule           = 17
	ObjectAveraging          = 18
	ObjectMultiStateValue    = 19
	ObjectTrendLog           = 20
	ObjectLifeSafetyPoint    = 21
	ObjectLifeSafetyZone     = 22
	ObjectAccumulator        = 23
	ObjectPulseConverter     = 24
	ObjectEventLog           = 25
	ObjectGlobalGroup        = 26
	ObjectTrendLogMultiple   = 27
	ObjectLoadControl        = 28
	ObjectStructuredView     = 29
	ObjectAccessDoor         = 30
	ObjectAccessCredential   = 32
	ObjectAccessPoint        = 33
	ObjectAccessRights       = 34
	ObjectAccessUser         = 35
	ObjectAccessZone         = 36
	ObjectCredentialDataInput = 37
	ObjectNetworkSecurity    = 38
	ObjectBitstringValue     = 39
	ObjectCharacterStringValue = 40
	ObjectDatePatternValue   = 41
	ObjectDateValue          = 42
	ObjectDateTimePatternValue = 43
	ObjectDateTimeValue      = 44
	ObjectIntegerValue       = 45
	ObjectLargeAnalogValue   = 46
	ObjectOctetStringValue   = 47
	ObjectPositiveIntegerValue = 48
	ObjectTimePatternValue   = 49
	ObjectTimeValue          = 50
	ObjectNotificationForwarder = 51
	ObjectAlertEnrollment    = 52
	ObjectChannel            = 53
	ObjectLightingOutput     = 54
)

// Security-relevant services
var securityRelevantServices = map[int]bool{
	ServiceDeviceCommunicationControl: true,
	ServiceReinitializeDevice:         true,
	ServiceConfirmedPrivateTransfer:   true,
}

// Critical operation services (affect building control)
var criticalOperationServices = map[int]bool{
	ServiceWriteProperty:         true,
	ServiceWritePropertyMultiple: true,
	ServiceCreateObject:          true,
	ServiceDeleteObject:          true,
	ServiceAddListElement:        true,
	ServiceRemoveListElement:     true,
	ServiceAtomicWriteFile:       true,
	ServiceReinitializeDevice:    true,
	ServiceLifeSafetyOperation:   true,
}

type bacnetipReader struct {
	conversation *core.ConversationInfo
}

// New returns a new BACnet/IP reader.
func (b *bacnetipReader) New(conversation *core.ConversationInfo) core.StreamDecoderInterface {
	return &bacnetipReader{
		conversation: conversation,
	}
}

// Decode parses BACnet/IP messages from the stream.
func (b *bacnetipReader) Decode() {
	if Decoder.Writer == nil {
		bacnetipLog.Error("BACnetIP Decoder.Writer is nil")
		return
	}

	// BACnet/IP is UDP-based, each datagram is a complete message
	for _, data := range b.conversation.Data {
		frameData := data.Raw()
		if len(frameData) < minBVLCHeaderSize {
			continue
		}

		msg := b.parseBACnetIPMessage(frameData)
		if msg != nil {
			msg.SrcIP = b.conversation.ClientIP
			msg.DstIP = b.conversation.ServerIP
			msg.SrcPort = int32(b.conversation.ClientPort)
			msg.DstPort = int32(b.conversation.ServerPort)

			err := Decoder.Writer.Write(msg)
			if err != nil {
				bacnetipLog.Error("failed to write BACnetIP record", zap.Error(err))
			} else {
				atomic.AddInt64(&Decoder.NumRecordsWritten, 1)
			}
		}
	}
}

// parseBACnetIPMessage parses a complete BACnet/IP message.
func (b *bacnetipReader) parseBACnetIPMessage(data []byte) *types.BACnetIP {
	if len(data) < minBVLCHeaderSize {
		return nil
	}

	// BVLC Header
	bvlcType := data[0]
	if bvlcType != bvlcTypeBACnetIP {
		return nil
	}

	bvlcFunction := data[1]
	bvlcLength := uint16(data[2])<<8 | uint16(data[3])

	msg := &types.BACnetIP{
		Timestamp:        b.conversation.FirstClientPacket.UnixNano(),
		BVLCType:         int32(bvlcType),
		BVLCFunction:     int32(bvlcFunction),
		BVLCFunctionName: GetBVLCFunctionName(bvlcFunction),
		BVLCLength:       int32(bvlcLength),
	}

	// Determine offset to NPDU based on BVLC function
	var npduOffset int
	switch bvlcFunction {
	case BVLCOriginalUnicastNPDU, BVLCOriginalBroadcastNPDU:
		npduOffset = 4 // Right after BVLC header
	case BVLCForwardedNPDU:
		npduOffset = 10 // BVLC header (4) + Originating IP (4) + Port (2)
	case BVLCDistributeBroadcastToNetwork:
		npduOffset = 4
	default:
		// Other BVLC functions don't have NPDU
		return msg
	}

	if len(data) <= npduOffset {
		return msg
	}

	// Parse NPDU
	b.parseNPDU(msg, data[npduOffset:])

	// Include payload if configured
	if decoderconfig.Instance.IncludePayloads && len(data) > npduOffset {
		msg.Payload = make([]byte, len(data)-npduOffset)
		copy(msg.Payload, data[npduOffset:])
	}

	return msg
}

// parseNPDU parses the Network Protocol Data Unit.
func (b *bacnetipReader) parseNPDU(msg *types.BACnetIP, data []byte) {
	if len(data) < minNPDUHeaderSize {
		return
	}

	msg.NPDUVersion = int32(data[0])
	npduControl := data[1]
	msg.NPDUControl = int32(npduControl)

	// Parse control bits
	msg.NPDUNetworkLayerMsg = (npduControl & 0x80) != 0
	msg.NPDUExpectsReply = (npduControl & 0x04) != 0
	msg.NPDUPriority = int32(npduControl & 0x03)

	offset := 2

	// Check for DNET/DADR (destination specifier)
	hasDNET := (npduControl & 0x20) != 0
	if hasDNET && len(data) > offset+2 {
		msg.DNET = int32(uint16(data[offset])<<8 | uint16(data[offset+1]))
		offset += 2

		// DLEN and DADR
		if len(data) > offset {
			dlen := int(data[offset])
			offset++
			if dlen > 0 && len(data) >= offset+dlen {
				msg.DADR = hex.EncodeToString(data[offset : offset+dlen])
				offset += dlen
			}
		}
	}

	// Check for SNET/SADR (source specifier)
	hasSNET := (npduControl & 0x08) != 0
	if hasSNET && len(data) > offset+2 {
		msg.SNET = int32(uint16(data[offset])<<8 | uint16(data[offset+1]))
		offset += 2

		// SLEN and SADR
		if len(data) > offset {
			slen := int(data[offset])
			offset++
			if slen > 0 && len(data) >= offset+slen {
				msg.SADR = hex.EncodeToString(data[offset : offset+slen])
				offset += slen
			}
		}
	}

	// Hop count (if DNET is present)
	if hasDNET && len(data) > offset {
		msg.HopCount = int32(data[offset])
		offset++
	}

	// Check if this is a network layer message or application layer
	if msg.NPDUNetworkLayerMsg {
		// Parse network layer message
		if len(data) > offset {
			msg.NetworkMessageType = int32(data[offset])
			msg.NetworkMessageTypeName = getNetworkMessageTypeName(uint8(msg.NetworkMessageType))
		}
	} else {
		// Parse APDU (Application Protocol Data Unit)
		if len(data) > offset {
			b.parseAPDU(msg, data[offset:])
		}
	}
}

// parseAPDU parses the Application Protocol Data Unit.
func (b *bacnetipReader) parseAPDU(msg *types.BACnetIP, data []byte) {
	if len(data) < 1 {
		return
	}

	// APDU type is in upper nibble of first byte
	apduType := (data[0] >> 4) & 0x0F
	msg.APDUType = int32(apduType)
	msg.APDUTypeName = getAPDUTypeName(apduType)

	switch apduType {
	case APDUConfirmedRequest:
		b.parseConfirmedRequest(msg, data)
	case APDUUnconfirmedRequest:
		b.parseUnconfirmedRequest(msg, data)
	case APDUSimpleAck:
		b.parseSimpleAck(msg, data)
	case APDUComplexAck:
		b.parseComplexAck(msg, data)
	case APDUSegmentAck:
		b.parseSegmentAck(msg, data)
	case APDUError:
		b.parseError(msg, data)
	case APDUReject:
		b.parseReject(msg, data)
	case APDUAbort:
		b.parseAbort(msg, data)
	}
}

// parseConfirmedRequest parses a confirmed service request.
func (b *bacnetipReader) parseConfirmedRequest(msg *types.BACnetIP, data []byte) {
	if len(data) < 3 {
		return
	}

	msg.IsConfirmed = true

	// Parse PDU flags
	pduFlags := data[0]
	msg.SegmentedMessage = int32((pduFlags >> 3) & 0x01)
	msg.MoreFollows = (pduFlags & 0x04) != 0
	msg.SegmentedResponseAccepted = (pduFlags & 0x02) != 0

	offset := 1

	// Max segments and max APDU length accepted
	if len(data) > offset {
		offset++ // Skip max-segments-accepted / max-APDU-length-accepted
	}

	// Invoke ID
	if len(data) > offset {
		msg.InvokeID = int32(data[offset])
		offset++
	}

	// Sequence number and proposed window size (if segmented)
	if msg.SegmentedMessage != 0 && len(data) > offset+1 {
		msg.SequenceNumber = int32(data[offset])
		msg.ProposedWindowSize = int32(data[offset+1])
		offset += 2
	}

	// Service choice
	if len(data) > offset {
		msg.ServiceChoice = int32(data[offset])
		msg.ServiceName = getConfirmedServiceName(uint8(msg.ServiceChoice))
		offset++

		// Check security relevance
		msg.IsSecurityRelevant = securityRelevantServices[int(msg.ServiceChoice)]
		msg.IsCriticalOperation = criticalOperationServices[int(msg.ServiceChoice)]
	}

	// Try to parse service-specific data (object identifier, property, etc.)
	if len(data) > offset {
		b.parseServiceData(msg, data[offset:])
	}
}

// parseUnconfirmedRequest parses an unconfirmed service request.
func (b *bacnetipReader) parseUnconfirmedRequest(msg *types.BACnetIP, data []byte) {
	if len(data) < 2 {
		return
	}

	msg.IsConfirmed = false

	// Service choice
	msg.ServiceChoice = int32(data[1])
	msg.ServiceName = getUnconfirmedServiceName(uint8(msg.ServiceChoice))

	// Try to parse service-specific data
	if len(data) > 2 {
		b.parseServiceData(msg, data[2:])
	}
}

// parseSimpleAck parses a simple acknowledgment.
func (b *bacnetipReader) parseSimpleAck(msg *types.BACnetIP, data []byte) {
	if len(data) < 3 {
		return
	}

	msg.InvokeID = int32(data[1])
	msg.ServiceChoice = int32(data[2])
	msg.ServiceName = getConfirmedServiceName(uint8(msg.ServiceChoice))
}

// parseComplexAck parses a complex acknowledgment.
func (b *bacnetipReader) parseComplexAck(msg *types.BACnetIP, data []byte) {
	if len(data) < 3 {
		return
	}

	pduFlags := data[0]
	msg.SegmentedMessage = int32((pduFlags >> 3) & 0x01)
	msg.MoreFollows = (pduFlags & 0x04) != 0

	offset := 1

	msg.InvokeID = int32(data[offset])
	offset++

	// Sequence number and proposed window size (if segmented)
	if msg.SegmentedMessage != 0 && len(data) > offset+1 {
		msg.SequenceNumber = int32(data[offset])
		msg.ProposedWindowSize = int32(data[offset+1])
		offset += 2
	}

	if len(data) > offset {
		msg.ServiceChoice = int32(data[offset])
		msg.ServiceName = getConfirmedServiceName(uint8(msg.ServiceChoice))
	}
}

// parseSegmentAck parses a segment acknowledgment.
func (b *bacnetipReader) parseSegmentAck(msg *types.BACnetIP, data []byte) {
	if len(data) < 4 {
		return
	}

	msg.InvokeID = int32(data[1])
	msg.SequenceNumber = int32(data[2])
	msg.ProposedWindowSize = int32(data[3])
}

// parseError parses an error PDU.
func (b *bacnetipReader) parseError(msg *types.BACnetIP, data []byte) {
	if len(data) < 3 {
		return
	}

	msg.InvokeID = int32(data[1])
	msg.ServiceChoice = int32(data[2])
	msg.ServiceName = getConfirmedServiceName(uint8(msg.ServiceChoice))

	// Error class and code follow in the error payload
	if len(data) > 4 {
		// Error class is typically at offset 3 as a context tag
		// Error code follows
		// This is a simplified parse - full ASN.1 BER parsing would be needed for complete decode
		msg.ErrorClass = int32(data[3] & 0x0F)
		if len(data) > 5 {
			msg.ErrorCode = int32(data[5] & 0x0F)
		}
		msg.ErrorName = getErrorName(uint8(msg.ErrorClass), uint8(msg.ErrorCode))
	}
}

// parseReject parses a reject PDU.
func (b *bacnetipReader) parseReject(msg *types.BACnetIP, data []byte) {
	if len(data) < 3 {
		return
	}

	msg.InvokeID = int32(data[1])
	msg.RejectReason = int32(data[2])
}

// parseAbort parses an abort PDU.
func (b *bacnetipReader) parseAbort(msg *types.BACnetIP, data []byte) {
	if len(data) < 3 {
		return
	}

	msg.InvokeID = int32(data[1])
	msg.AbortReason = int32(data[2])
}

// parseServiceData attempts to parse object identifier and property from service data.
// This is a simplified parser - full BACnet ASN.1 BER parsing is complex.
func (b *bacnetipReader) parseServiceData(msg *types.BACnetIP, data []byte) {
	if len(data) < 4 {
		return
	}

	// Look for object identifier (context tag 0, length 4)
	offset := 0
	for offset < len(data)-4 {
		tagNum := (data[offset] >> 4) & 0x0F
		tagClass := (data[offset] >> 3) & 0x01
		tagLen := data[offset] & 0x07

		// Object identifier is typically context tag 0 with length 4
		if tagClass == 1 && tagNum == 0 && tagLen == 4 && offset+5 <= len(data) {
			// Object identifier is 4 bytes
			objId := uint32(data[offset+1])<<24 | uint32(data[offset+2])<<16 | uint32(data[offset+3])<<8 | uint32(data[offset+4])
			msg.ObjectType = int32((objId >> 22) & 0x3FF)
			msg.ObjectInstance = objId & 0x3FFFFF
			msg.ObjectTypeName = getObjectTypeName(uint16(msg.ObjectType))
			offset += 5
			break
		}

		// Skip this tag
		if tagLen == 5 {
			// Extended length
			if offset+1 < len(data) {
				tagLen = data[offset+1]
				offset += 2 + int(tagLen)
			} else {
				break
			}
		} else {
			offset += 1 + int(tagLen)
		}
	}

	// Look for property identifier (context tag 1)
	for offset < len(data)-2 {
		tagNum := (data[offset] >> 4) & 0x0F
		tagClass := (data[offset] >> 3) & 0x01
		tagLen := data[offset] & 0x07

		if tagClass == 1 && tagNum == 1 && tagLen > 0 && offset+1+int(tagLen) <= len(data) {
			// Property identifier
			propId := 0
			for i := 0; i < int(tagLen); i++ {
				propId = propId<<8 | int(data[offset+1+i])
			}
			msg.PropertyIdentifier = int32(propId)
			msg.PropertyName = getPropertyName(uint32(propId))
			break
		}

		// Skip this tag
		if tagLen == 5 {
			if offset+1 < len(data) {
				tagLen = data[offset+1]
				offset += 2 + int(tagLen)
			} else {
				break
			}
		} else {
			offset += 1 + int(tagLen)
		}
	}
}

// Helper functions for human-readable names

func getAPDUTypeName(apduType uint8) string {
	switch apduType {
	case APDUConfirmedRequest:
		return "Confirmed-Request"
	case APDUUnconfirmedRequest:
		return "Unconfirmed-Request"
	case APDUSimpleAck:
		return "Simple-Ack"
	case APDUComplexAck:
		return "Complex-Ack"
	case APDUSegmentAck:
		return "Segment-Ack"
	case APDUError:
		return "Error"
	case APDUReject:
		return "Reject"
	case APDUAbort:
		return "Abort"
	default:
		return "Unknown"
	}
}

func getNetworkMessageTypeName(msgType uint8) string {
	switch msgType {
	case NetworkWhoIsRouterToNetwork:
		return "Who-Is-Router-To-Network"
	case NetworkIAmRouterToNetwork:
		return "I-Am-Router-To-Network"
	case NetworkICouldBeRouterToNetwork:
		return "I-Could-Be-Router-To-Network"
	case NetworkRejectMessageToNetwork:
		return "Reject-Message-To-Network"
	case NetworkRouterBusyToNetwork:
		return "Router-Busy-To-Network"
	case NetworkRouterAvailableToNetwork:
		return "Router-Available-To-Network"
	case NetworkInitRouteTable:
		return "Initialize-Routing-Table"
	case NetworkInitRouteTableAck:
		return "Initialize-Routing-Table-Ack"
	case NetworkEstablishConnectionToNetwork:
		return "Establish-Connection-To-Network"
	case NetworkDisconnectConnectionToNetwork:
		return "Disconnect-Connection-To-Network"
	case NetworkWhatIsNetworkNumber:
		return "What-Is-Network-Number"
	case NetworkNetworkNumberIs:
		return "Network-Number-Is"
	default:
		return "Unknown"
	}
}

func getConfirmedServiceName(choice uint8) string {
	switch choice {
	case ServiceAcknowledgeAlarm:
		return "AcknowledgeAlarm"
	case ServiceConfirmedCOVNotification:
		return "ConfirmedCOVNotification"
	case ServiceConfirmedEventNotification:
		return "ConfirmedEventNotification"
	case ServiceGetAlarmSummary:
		return "GetAlarmSummary"
	case ServiceGetEnrollmentSummary:
		return "GetEnrollmentSummary"
	case ServiceSubscribeCOV:
		return "SubscribeCOV"
	case ServiceAtomicReadFile:
		return "AtomicReadFile"
	case ServiceAtomicWriteFile:
		return "AtomicWriteFile"
	case ServiceAddListElement:
		return "AddListElement"
	case ServiceRemoveListElement:
		return "RemoveListElement"
	case ServiceCreateObject:
		return "CreateObject"
	case ServiceDeleteObject:
		return "DeleteObject"
	case ServiceReadProperty:
		return "ReadProperty"
	case ServiceReadPropertyConditional:
		return "ReadPropertyConditional"
	case ServiceReadPropertyMultiple:
		return "ReadPropertyMultiple"
	case ServiceWriteProperty:
		return "WriteProperty"
	case ServiceWritePropertyMultiple:
		return "WritePropertyMultiple"
	case ServiceDeviceCommunicationControl:
		return "DeviceCommunicationControl"
	case ServiceConfirmedPrivateTransfer:
		return "ConfirmedPrivateTransfer"
	case ServiceConfirmedTextMessage:
		return "ConfirmedTextMessage"
	case ServiceReinitializeDevice:
		return "ReinitializeDevice"
	case ServiceVTOpen:
		return "VTOpen"
	case ServiceVTClose:
		return "VTClose"
	case ServiceVTData:
		return "VTData"
	case ServiceReadRange:
		return "ReadRange"
	case ServiceLifeSafetyOperation:
		return "LifeSafetyOperation"
	case ServiceSubscribeCOVProperty:
		return "SubscribeCOVProperty"
	default:
		return "Unknown"
	}
}

func getUnconfirmedServiceName(choice uint8) string {
	switch choice {
	case ServiceIAm:
		return "I-Am"
	case ServiceIHave:
		return "I-Have"
	case ServiceUnconfirmedCOVNotification:
		return "UnconfirmedCOVNotification"
	case ServiceUnconfirmedEventNotification:
		return "UnconfirmedEventNotification"
	case ServiceUnconfirmedPrivateTransfer:
		return "UnconfirmedPrivateTransfer"
	case ServiceUnconfirmedTextMessage:
		return "UnconfirmedTextMessage"
	case ServiceTimeSynchronization:
		return "TimeSynchronization"
	case ServiceWhoHas:
		return "Who-Has"
	case ServiceWhoIs:
		return "Who-Is"
	case ServiceUTCTimeSynchronization:
		return "UTCTimeSynchronization"
	case ServiceWriteGroup:
		return "WriteGroup"
	case ServiceUnconfirmedCOVNotificationMultiple:
		return "UnconfirmedCOVNotificationMultiple"
	default:
		return "Unknown"
	}
}

func getObjectTypeName(objType uint16) string {
	switch objType {
	case ObjectAnalogInput:
		return "analog-input"
	case ObjectAnalogOutput:
		return "analog-output"
	case ObjectAnalogValue:
		return "analog-value"
	case ObjectBinaryInput:
		return "binary-input"
	case ObjectBinaryOutput:
		return "binary-output"
	case ObjectBinaryValue:
		return "binary-value"
	case ObjectCalendar:
		return "calendar"
	case ObjectCommand:
		return "command"
	case ObjectDevice:
		return "device"
	case ObjectEventEnrollment:
		return "event-enrollment"
	case ObjectFile:
		return "file"
	case ObjectGroup:
		return "group"
	case ObjectLoop:
		return "loop"
	case ObjectMultiStateInput:
		return "multi-state-input"
	case ObjectMultiStateOutput:
		return "multi-state-output"
	case ObjectNotificationClass:
		return "notification-class"
	case ObjectProgram:
		return "program"
	case ObjectSchedule:
		return "schedule"
	case ObjectAveraging:
		return "averaging"
	case ObjectMultiStateValue:
		return "multi-state-value"
	case ObjectTrendLog:
		return "trend-log"
	case ObjectLifeSafetyPoint:
		return "life-safety-point"
	case ObjectLifeSafetyZone:
		return "life-safety-zone"
	case ObjectAccumulator:
		return "accumulator"
	case ObjectPulseConverter:
		return "pulse-converter"
	case ObjectEventLog:
		return "event-log"
	case ObjectGlobalGroup:
		return "global-group"
	case ObjectTrendLogMultiple:
		return "trend-log-multiple"
	case ObjectLoadControl:
		return "load-control"
	case ObjectStructuredView:
		return "structured-view"
	case ObjectAccessDoor:
		return "access-door"
	case ObjectAccessCredential:
		return "access-credential"
	case ObjectAccessPoint:
		return "access-point"
	case ObjectAccessRights:
		return "access-rights"
	case ObjectAccessUser:
		return "access-user"
	case ObjectAccessZone:
		return "access-zone"
	case ObjectCredentialDataInput:
		return "credential-data-input"
	case ObjectNetworkSecurity:
		return "network-security"
	case ObjectChannel:
		return "channel"
	case ObjectLightingOutput:
		return "lighting-output"
	default:
		return "unknown"
	}
}

func getPropertyName(propId uint32) string {
	// Common property identifiers
	switch propId {
	case 0:
		return "acked-transitions"
	case 1:
		return "ack-required"
	case 17:
		return "change-of-state-count"
	case 19:
		return "change-of-state-time"
	case 28:
		return "description"
	case 36:
		return "event-state"
	case 44:
		return "high-limit"
	case 45:
		return "inactive-text"
	case 46:
		return "in-process"
	case 55:
		return "limit-enable"
	case 59:
		return "low-limit"
	case 70:
		return "max-pres-value"
	case 72:
		return "min-pres-value"
	case 75:
		return "object-identifier"
	case 76:
		return "object-list"
	case 77:
		return "object-name"
	case 79:
		return "object-type"
	case 81:
		return "out-of-service"
	case 84:
		return "polarity"
	case 85:
		return "present-value"
	case 87:
		return "priority-array"
	case 102:
		return "relinquish-default"
	case 103:
		return "required"
	case 104:
		return "resolution"
	case 111:
		return "status-flags"
	case 117:
		return "time-delay"
	case 120:
		return "units"
	case 127:
		return "vendor-identifier"
	case 139:
		return "property-list"
	case 155:
		return "active-cov-subscriptions"
	case 168:
		return "profile-name"
	default:
		return "unknown"
	}
}

func getErrorName(errorClass uint8, errorCode uint8) string {
	// Map common error class/code combinations
	classNames := map[uint8]string{
		0: "device",
		1: "object",
		2: "property",
		3: "resources",
		4: "security",
		5: "services",
		6: "vt",
	}

	className := classNames[errorClass]
	if className == "" {
		className = "unknown"
	}

	return className
}

