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
	"sync/atomic"

	"go.uber.org/zap"

	decoderconfig "github.com/dreadl0ck/netcap/internal/decoder/config"
	"github.com/dreadl0ck/netcap/internal/decoder/core"
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
	ServiceAcknowledgeAlarm           = 0
	ServiceConfirmedCOVNotification   = 1
	ServiceConfirmedEventNotification = 2
	ServiceGetAlarmSummary            = 3
	ServiceGetEnrollmentSummary       = 4
	ServiceSubscribeCOV               = 5
	ServiceSubscribeCOVProperty       = 28
	ServiceLifeSafetyOperation        = 27

	// File Services
	ServiceAtomicReadFile  = 6
	ServiceAtomicWriteFile = 7

	// Object Access Services
	ServiceAddListElement          = 8
	ServiceRemoveListElement       = 9
	ServiceCreateObject            = 10
	ServiceDeleteObject            = 11
	ServiceReadProperty            = 12
	ServiceReadPropertyConditional = 13
	ServiceReadPropertyMultiple    = 14
	ServiceReadRange               = 26
	ServiceWriteProperty           = 15
	ServiceWritePropertyMultiple   = 16

	// Remote Device Management Services
	ServiceDeviceCommunicationControl = 17
	ServiceConfirmedPrivateTransfer   = 18
	ServiceConfirmedTextMessage       = 19
	ServiceReinitializeDevice         = 20

	// Virtual Terminal Services
	ServiceVTOpen  = 21
	ServiceVTClose = 22
	ServiceVTData  = 23
)

// Unconfirmed Service Choices
const (
	ServiceIAm                                = 0
	ServiceIHave                              = 1
	ServiceUnconfirmedCOVNotification         = 2
	ServiceUnconfirmedEventNotification       = 3
	ServiceUnconfirmedPrivateTransfer         = 4
	ServiceUnconfirmedTextMessage             = 5
	ServiceTimeSynchronization                = 6
	ServiceWhoHas                             = 7
	ServiceWhoIs                              = 8
	ServiceUTCTimeSynchronization             = 9
	ServiceWriteGroup                         = 10
	ServiceUnconfirmedCOVNotificationMultiple = 11
)

// Network Layer Message Types
const (
	NetworkWhoIsRouterToNetwork          = 0x00
	NetworkIAmRouterToNetwork            = 0x01
	NetworkICouldBeRouterToNetwork       = 0x02
	NetworkRejectMessageToNetwork        = 0x03
	NetworkRouterBusyToNetwork           = 0x04
	NetworkRouterAvailableToNetwork      = 0x05
	NetworkInitRouteTable                = 0x06
	NetworkInitRouteTableAck             = 0x07
	NetworkEstablishConnectionToNetwork  = 0x08
	NetworkDisconnectConnectionToNetwork = 0x09
	NetworkWhatIsNetworkNumber           = 0x12
	NetworkNetworkNumberIs               = 0x13
)

// Object Types
const (
	ObjectAnalogInput           = 0
	ObjectAnalogOutput          = 1
	ObjectAnalogValue           = 2
	ObjectBinaryInput           = 3
	ObjectBinaryOutput          = 4
	ObjectBinaryValue           = 5
	ObjectCalendar              = 6
	ObjectCommand               = 7
	ObjectDevice                = 8
	ObjectEventEnrollment       = 9
	ObjectFile                  = 10
	ObjectGroup                 = 11
	ObjectLoop                  = 12
	ObjectMultiStateInput       = 13
	ObjectMultiStateOutput      = 14
	ObjectNotificationClass     = 15
	ObjectProgram               = 16
	ObjectSchedule              = 17
	ObjectAveraging             = 18
	ObjectMultiStateValue       = 19
	ObjectTrendLog              = 20
	ObjectLifeSafetyPoint       = 21
	ObjectLifeSafetyZone        = 22
	ObjectAccumulator           = 23
	ObjectPulseConverter        = 24
	ObjectEventLog              = 25
	ObjectGlobalGroup           = 26
	ObjectTrendLogMultiple      = 27
	ObjectLoadControl           = 28
	ObjectStructuredView        = 29
	ObjectAccessDoor            = 30
	ObjectAccessCredential      = 32
	ObjectAccessPoint           = 33
	ObjectAccessRights          = 34
	ObjectAccessUser            = 35
	ObjectAccessZone            = 36
	ObjectCredentialDataInput   = 37
	ObjectNetworkSecurity       = 38
	ObjectBitstringValue        = 39
	ObjectCharacterStringValue  = 40
	ObjectDatePatternValue      = 41
	ObjectDateValue             = 42
	ObjectDateTimePatternValue  = 43
	ObjectDateTimeValue         = 44
	ObjectIntegerValue          = 45
	ObjectLargeAnalogValue      = 46
	ObjectOctetStringValue      = 47
	ObjectPositiveIntegerValue  = 48
	ObjectTimePatternValue      = 49
	ObjectTimeValue             = 50
	ObjectNotificationForwarder = 51
	ObjectAlertEnrollment       = 52
	ObjectChannel               = 53
	ObjectLightingOutput        = 54
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
	for data := range b.conversation.Fragments() {
		frameData := data.Raw()
		if len(frameData) < minBVLCHeaderSize {
			continue
		}

		msg := b.parseBACnetIPMessage(frameData)
		if msg != nil {
			// Time and direction come from the datagram that carried the
			// message. Every record used to take FirstClientPacket and the
			// client's addresses, which collapses a session to one instant and
			// records a reply as though the client had sent it.
			msg.SrcIP, msg.DstIP, msg.SrcPort, msg.DstPort = b.conversation.Endpoints(data)
			msg.Timestamp = core.FragmentTime(data)
			msg.CommunityID = b.conversation.CommunityID

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
	if int(bvlcLength) != len(data) || !isValidBVLCFunction(bvlcFunction) {
		msg.ParseQualifications = []string{"invalid-BVLC-length-or-function"}
		return msg
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
	parseSharedNPDU(msg, data[npduOffset:])

	// Include payload if configured
	if decoderconfig.Instance.IncludePayloads && len(data) > npduOffset {
		msg.Payload = make([]byte, len(data)-npduOffset)
		copy(msg.Payload, data[npduOffset:])
	}

	return msg
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
