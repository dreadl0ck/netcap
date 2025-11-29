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
	"bytes"
	"encoding/binary"
	"strconv"
	"sync/atomic"

	"go.uber.org/zap"

	"github.com/dreadl0ck/netcap/decoder/core"
	"github.com/dreadl0ck/netcap/types"
)

// OPC UA Service IDs (subset of commonly used services)
const (
	// Discovery Services
	ServiceFindServers           = 422
	ServiceFindServersOnNetwork  = 12208
	ServiceGetEndpoints          = 428
	ServiceRegisterServer        = 437
	ServiceRegisterServer2       = 12211

	// SecureChannel Services
	ServiceOpenSecureChannel  = 446
	ServiceCloseSecureChannel = 452

	// Session Services
	ServiceCreateSession  = 461
	ServiceActivateSession = 467
	ServiceCloseSession    = 473
	ServiceCancel          = 479

	// Node Management Services
	ServiceAddNodes       = 488
	ServiceAddReferences  = 494
	ServiceDeleteNodes    = 500
	ServiceDeleteReferences = 506

	// View Services
	ServiceBrowse       = 527
	ServiceBrowseNext   = 533
	ServiceTranslateBrowsePathsToNodeIds = 554

	// Query Services
	ServiceQueryFirst = 615
	ServiceQueryNext  = 621

	// Attribute Services
	ServiceRead         = 631
	ServiceHistoryRead  = 664
	ServiceWrite        = 673
	ServiceHistoryUpdate = 700

	// Method Services
	ServiceCall = 712

	// MonitoredItem Services
	ServiceCreateMonitoredItems = 751
	ServiceModifyMonitoredItems = 763
	ServiceSetMonitoringMode    = 769
	ServiceSetTriggering        = 775
	ServiceDeleteMonitoredItems = 781

	// Subscription Services
	ServiceCreateSubscription   = 787
	ServiceModifySubscription   = 793
	ServiceSetPublishingMode    = 799
	ServicePublish              = 826
	ServiceRepublish            = 832
	ServiceTransferSubscriptions = 841
	ServiceDeleteSubscriptions  = 847
)

// Security-relevant service IDs
var securityRelevantServices = map[uint32]bool{
	ServiceOpenSecureChannel:  true,
	ServiceCloseSecureChannel: true,
	ServiceCreateSession:      true,
	ServiceActivateSession:    true,
	ServiceCloseSession:       true,
	ServiceRegisterServer:     true,
	ServiceRegisterServer2:    true,
}

// Critical operation service IDs (affect process control)
var criticalOperationServices = map[uint32]bool{
	ServiceWrite:         true,
	ServiceHistoryUpdate: true,
	ServiceCall:          true,
	ServiceAddNodes:      true,
	ServiceDeleteNodes:   true,
	ServiceAddReferences: true,
	ServiceDeleteReferences: true,
}

// OPC UA Security Modes
const (
	SecurityModeInvalid        = 0
	SecurityModeNone           = 1
	SecurityModeSign           = 2
	SecurityModeSignAndEncrypt = 3
)

type opcuaReader struct {
	conversation *core.ConversationInfo
}

// New returns a new OPC UA reader.
func (o *opcuaReader) New(conversation *core.ConversationInfo) core.StreamDecoderInterface {
	return &opcuaReader{
		conversation: conversation,
	}
}

// Decode parses OPC UA messages from the stream.
func (o *opcuaReader) Decode() {
	if Decoder.Writer == nil {
		opcuaLog.Error("OPCUA Decoder.Writer is nil")
		return
	}

	var buf bytes.Buffer

	for _, data := range o.conversation.Data {
		buf.Write(data.Raw())
	}

	frameData := buf.Bytes()
	offset := 0

	for offset < len(frameData)-minHeaderSize {
		// Check for OPC UA message header
		if !o.isOPCUAHeader(frameData[offset:]) {
			offset++
			continue
		}

		msg, consumed := o.parseOPCUAMessage(frameData[offset:])
		if msg != nil {
			msg.SrcIP = o.conversation.ClientIP
			msg.DstIP = o.conversation.ServerIP
			msg.SrcPort = int32(o.conversation.ClientPort)
			msg.DstPort = int32(o.conversation.ServerPort)

			err := Decoder.Writer.Write(msg)
			if err != nil {
				opcuaLog.Error("failed to write OPCUA record", zap.Error(err))
			} else {
				atomic.AddInt64(&Decoder.NumRecordsWritten, 1)
			}
		}

		if consumed > 0 {
			offset += consumed
		} else {
			offset++
		}
	}
}

// isOPCUAHeader checks if the data starts with a valid OPC UA header.
func (o *opcuaReader) isOPCUAHeader(data []byte) bool {
	if len(data) < minHeaderSize {
		return false
	}

	// Check message type
	msgType := string(data[0:3])
	switch msgType {
	case msgTypeHello, msgTypeAcknowledge, msgTypeError,
		msgTypeReverseHello, msgTypeOpenChannel, msgTypeCloseChannel, msgTypeMessage:
		// Valid message type
	default:
		return false
	}

	// Check chunk type
	switch data[3] {
	case chunkIntermediate, chunkFinal, chunkAbort:
		// Valid
	default:
		return false
	}

	return true
}

// parseOPCUAMessage parses an OPC UA message and returns the parsed record and bytes consumed.
func (o *opcuaReader) parseOPCUAMessage(data []byte) (*types.OPCUA, int) {
	if len(data) < minHeaderSize {
		return nil, 0
	}

	msgType := string(data[0:3])
	chunkType := string(data[3:4])
	messageSize := binary.LittleEndian.Uint32(data[4:8])

	// Validate message size
	if messageSize < minHeaderSize || messageSize > uint32(len(data)) {
		return nil, 0
	}

	msg := &types.OPCUA{
		Timestamp:   o.conversation.FirstClientPacket.UnixNano(),
		MessageType: msgType,
		ChunkType:   chunkType,
		MessageSize: int32(messageSize),
	}

	// Parse based on message type
	switch msgType {
	case msgTypeHello:
		o.parseHelloMessage(msg, data)
	case msgTypeAcknowledge:
		o.parseAcknowledgeMessage(msg, data)
	case msgTypeError:
		o.parseErrorMessage(msg, data)
	case msgTypeReverseHello:
		o.parseReverseHelloMessage(msg, data)
	case msgTypeOpenChannel:
		o.parseSecureChannelMessage(msg, data)
	case msgTypeCloseChannel:
		o.parseSecureChannelMessage(msg, data)
	case msgTypeMessage:
		o.parseSecureMessage(msg, data)
	}

	return msg, int(messageSize)
}

// parseHelloMessage parses a Hello (HEL) message.
// Format: Header (8) + ProtocolVersion (4) + ReceiveBufferSize (4) + SendBufferSize (4)
//         + MaxMessageSize (4) + MaxChunkCount (4) + EndpointUrl (length-prefixed string)
func (o *opcuaReader) parseHelloMessage(msg *types.OPCUA, data []byte) {
	if len(data) < 28 {
		return
	}

	msg.ProtocolVersion = int32(binary.LittleEndian.Uint32(data[8:12]))
	msg.ReceiveBufferSize = int32(binary.LittleEndian.Uint32(data[12:16]))
	msg.SendBufferSize = int32(binary.LittleEndian.Uint32(data[16:20]))
	msg.MaxMessageSize = int32(binary.LittleEndian.Uint32(data[20:24]))
	msg.MaxChunkCount = int32(binary.LittleEndian.Uint32(data[24:28]))

	// Parse EndpointUrl (length-prefixed UTF-8 string)
	if len(data) >= 32 {
		urlLen := binary.LittleEndian.Uint32(data[28:32])
		if urlLen > 0 && urlLen < 4096 && len(data) >= int(32+urlLen) {
			msg.EndpointUrl = string(data[32 : 32+urlLen])
		}
	}
}

// parseAcknowledgeMessage parses an Acknowledge (ACK) message.
// Format: Header (8) + ProtocolVersion (4) + ReceiveBufferSize (4) + SendBufferSize (4)
//         + MaxMessageSize (4) + MaxChunkCount (4)
func (o *opcuaReader) parseAcknowledgeMessage(msg *types.OPCUA, data []byte) {
	if len(data) < 28 {
		return
	}

	msg.ProtocolVersion = int32(binary.LittleEndian.Uint32(data[8:12]))
	msg.ReceiveBufferSize = int32(binary.LittleEndian.Uint32(data[12:16]))
	msg.SendBufferSize = int32(binary.LittleEndian.Uint32(data[16:20]))
	msg.MaxMessageSize = int32(binary.LittleEndian.Uint32(data[20:24]))
	msg.MaxChunkCount = int32(binary.LittleEndian.Uint32(data[24:28]))
}

// parseErrorMessage parses an Error (ERR) message.
// Format: Header (8) + ErrorCode (4) + Reason (length-prefixed string)
func (o *opcuaReader) parseErrorMessage(msg *types.OPCUA, data []byte) {
	if len(data) < 12 {
		return
	}

	msg.ErrorCode = binary.LittleEndian.Uint32(data[8:12])

	// Parse error reason (length-prefixed UTF-8 string)
	if len(data) >= 16 {
		reasonLen := binary.LittleEndian.Uint32(data[12:16])
		if reasonLen > 0 && reasonLen < 4096 && len(data) >= int(16+reasonLen) {
			msg.ErrorReason = string(data[16 : 16+reasonLen])
		}
	}
}

// parseReverseHelloMessage parses a Reverse Hello (RHE) message.
// Format: Header (8) + ServerUri (length-prefixed) + EndpointUrl (length-prefixed)
func (o *opcuaReader) parseReverseHelloMessage(msg *types.OPCUA, data []byte) {
	if len(data) < 12 {
		return
	}

	offset := 8

	// Parse ServerUri (skipped, but advance offset)
	if offset+4 <= len(data) {
		serverUriLen := binary.LittleEndian.Uint32(data[offset : offset+4])
		offset += 4
		if serverUriLen > 0 && serverUriLen < 4096 && offset+int(serverUriLen) <= len(data) {
			offset += int(serverUriLen)
		}
	}

	// Parse EndpointUrl
	if offset+4 <= len(data) {
		urlLen := binary.LittleEndian.Uint32(data[offset : offset+4])
		offset += 4
		if urlLen > 0 && urlLen < 4096 && offset+int(urlLen) <= len(data) {
			msg.EndpointUrl = string(data[offset : offset+int(urlLen)])
		}
	}
}

// parseSecureChannelMessage parses OpenSecureChannel (OPN) or CloseSecureChannel (CLO) messages.
// Format: Header (8) + SecureChannelId (4) + SecurityHeader + SequenceHeader + Payload
func (o *opcuaReader) parseSecureChannelMessage(msg *types.OPCUA, data []byte) {
	if len(data) < 12 {
		return
	}

	msg.SecureChannelId = binary.LittleEndian.Uint32(data[8:12])

	offset := 12

	// For OPN messages, parse the asymmetric security header
	if msg.MessageType == msgTypeOpenChannel {
		// SecurityPolicyUri (length-prefixed string)
		if offset+4 <= len(data) {
			policyLen := binary.LittleEndian.Uint32(data[offset : offset+4])
			offset += 4
			if policyLen > 0 && policyLen < 4096 && offset+int(policyLen) <= len(data) {
				msg.SecurityPolicyUri = string(data[offset : offset+int(policyLen)])
				offset += int(policyLen)
			}
		}

		// SenderCertificate (skipped)
		if offset+4 <= len(data) {
			certLen := binary.LittleEndian.Uint32(data[offset : offset+4])
			offset += 4
			if certLen > 0 && certLen < 65536 && offset+int(certLen) <= len(data) {
				offset += int(certLen)
			}
		}

		// ReceiverCertificateThumbprint (skipped)
		if offset+4 <= len(data) {
			thumbLen := binary.LittleEndian.Uint32(data[offset : offset+4])
			offset += 4
			if thumbLen > 0 && thumbLen < 256 && offset+int(thumbLen) <= len(data) {
				offset += int(thumbLen)
			}
		}

		// Mark as security-relevant
		msg.IsSecurityRelevant = true
	}

	// Parse sequence header
	if offset+8 <= len(data) {
		msg.SequenceNumber = binary.LittleEndian.Uint32(data[offset : offset+4])
		msg.RequestId = binary.LittleEndian.Uint32(data[offset+4 : offset+8])
		offset += 8
	}

	// For OPN, try to parse the service NodeId and determine request/response
	if msg.MessageType == msgTypeOpenChannel && offset < len(data) {
		o.parseServicePayload(msg, data[offset:])
	}
}

// parseSecureMessage parses a secured Message (MSG).
// Format: Header (8) + SecureChannelId (4) + TokenId (4) + SequenceHeader (8) + Payload
func (o *opcuaReader) parseSecureMessage(msg *types.OPCUA, data []byte) {
	if len(data) < 24 {
		return
	}

	msg.SecureChannelId = binary.LittleEndian.Uint32(data[8:12])
	// TokenId at data[12:16] (skipped)
	msg.SequenceNumber = binary.LittleEndian.Uint32(data[16:20])
	msg.RequestId = binary.LittleEndian.Uint32(data[20:24])

	// Parse service payload
	if len(data) > 24 {
		o.parseServicePayload(msg, data[24:])
	}
}

// parseServicePayload parses the service layer of an OPC UA message.
// The first element is a NodeId identifying the service type.
func (o *opcuaReader) parseServicePayload(msg *types.OPCUA, data []byte) {
	if len(data) < 1 {
		return
	}

	// Parse NodeId (identifier for the service)
	nodeId, nodeIdLen := o.parseNodeId(data)
	if nodeIdLen == 0 {
		return
	}

	msg.ServiceNodeId = nodeId.String()

	// Determine service name and whether it's a request or response
	serviceId := nodeId.NumericId
	msg.ServiceName = getServiceName(serviceId)
	msg.IsRequest = isRequestService(serviceId)

	// Check security relevance
	msg.IsSecurityRelevant = securityRelevantServices[serviceId]
	msg.IsCriticalOperation = criticalOperationServices[serviceId]

	offset := nodeIdLen

	// Try to parse RequestHeader or ResponseHeader for additional context
	if offset < len(data) {
		if msg.IsRequest {
			o.parseRequestHeader(msg, data[offset:])
		} else {
			o.parseResponseHeader(msg, data[offset:])
		}
	}
}

// NodeId represents an OPC UA NodeId.
type NodeId struct {
	EncodingType uint8
	Namespace    uint16
	NumericId    uint32
	StringId     string
}

func (n *NodeId) String() string {
	if n.StringId != "" {
		if n.Namespace == 0 {
			return "s=" + n.StringId
		}
		return "ns=" + strconv.FormatUint(uint64(n.Namespace), 10) + ";s=" + n.StringId
	}
	if n.Namespace == 0 {
		return "i=" + strconv.FormatUint(uint64(n.NumericId), 10)
	}
	return "ns=" + strconv.FormatUint(uint64(n.Namespace), 10) + ";i=" + strconv.FormatUint(uint64(n.NumericId), 10)
}

// parseNodeId parses an OPC UA NodeId from the data.
// Returns the NodeId and the number of bytes consumed.
func (o *opcuaReader) parseNodeId(data []byte) (NodeId, int) {
	if len(data) < 1 {
		return NodeId{}, 0
	}

	nodeId := NodeId{EncodingType: data[0] & 0x3F}

	switch nodeId.EncodingType {
	case 0x00: // Two-byte NodeId
		if len(data) < 2 {
			return NodeId{}, 0
		}
		nodeId.NumericId = uint32(data[1])
		return nodeId, 2

	case 0x01: // Four-byte NodeId
		if len(data) < 4 {
			return NodeId{}, 0
		}
		nodeId.Namespace = uint16(data[1])
		nodeId.NumericId = uint32(binary.LittleEndian.Uint16(data[2:4]))
		return nodeId, 4

	case 0x02: // Numeric NodeId
		if len(data) < 7 {
			return NodeId{}, 0
		}
		nodeId.Namespace = binary.LittleEndian.Uint16(data[1:3])
		nodeId.NumericId = binary.LittleEndian.Uint32(data[3:7])
		return nodeId, 7

	case 0x03: // String NodeId
		if len(data) < 7 {
			return NodeId{}, 0
		}
		nodeId.Namespace = binary.LittleEndian.Uint16(data[1:3])
		strLen := binary.LittleEndian.Uint32(data[3:7])
		if strLen > 4096 || len(data) < int(7+strLen) {
			return NodeId{}, 0
		}
		nodeId.StringId = string(data[7 : 7+strLen])
		return nodeId, int(7 + strLen)

	case 0x04: // GUID NodeId (skip parsing, just consume bytes)
		if len(data) < 19 { // 1 + 2 + 16 (GUID)
			return NodeId{}, 0
		}
		nodeId.Namespace = binary.LittleEndian.Uint16(data[1:3])
		return nodeId, 19

	case 0x05: // ByteString NodeId
		if len(data) < 7 {
			return NodeId{}, 0
		}
		nodeId.Namespace = binary.LittleEndian.Uint16(data[1:3])
		bsLen := binary.LittleEndian.Uint32(data[3:7])
		if bsLen > 4096 || len(data) < int(7+bsLen) {
			return NodeId{}, 0
		}
		return nodeId, int(7 + bsLen)
	}

	return NodeId{}, 0
}

// parseRequestHeader parses an OPC UA RequestHeader.
func (o *opcuaReader) parseRequestHeader(msg *types.OPCUA, data []byte) {
	// RequestHeader contains:
	// - AuthenticationToken (NodeId)
	// - Timestamp (DateTime - 8 bytes)
	// - RequestHandle (UInt32)
	// - ReturnDiagnostics (UInt32)
	// - AuditEntryId (String)
	// - TimeoutHint (UInt32)
	// - AdditionalHeader (ExtensionObject)

	if len(data) < 1 {
		return
	}

	// Parse AuthenticationToken NodeId
	authToken, authLen := o.parseNodeId(data)
	if authLen > 0 {
		msg.AuthenticationToken = authToken.String()
	}

	offset := authLen
	// Skip Timestamp (8 bytes) to get to RequestHandle
	if offset+12 <= len(data) {
		msg.RequestHandle = binary.LittleEndian.Uint32(data[offset+8 : offset+12])
	}
}

// parseResponseHeader parses an OPC UA ResponseHeader.
func (o *opcuaReader) parseResponseHeader(msg *types.OPCUA, data []byte) {
	// ResponseHeader contains:
	// - Timestamp (DateTime - 8 bytes)
	// - RequestHandle (UInt32)
	// - ServiceResult (StatusCode - UInt32)
	// - ServiceDiagnostics (DiagnosticInfo)
	// - StringTable (array of String)
	// - AdditionalHeader (ExtensionObject)

	if len(data) < 16 {
		return
	}

	msg.RequestHandle = binary.LittleEndian.Uint32(data[8:12])
	msg.StatusCode = binary.LittleEndian.Uint32(data[12:16])
	msg.StatusCodeName = getStatusCodeName(msg.StatusCode)
}

// getServiceName returns the human-readable name for an OPC UA service ID.
func getServiceName(serviceId uint32) string {
	switch serviceId {
	case ServiceFindServers:
		return "FindServers"
	case ServiceFindServersOnNetwork:
		return "FindServersOnNetwork"
	case ServiceGetEndpoints:
		return "GetEndpoints"
	case ServiceRegisterServer:
		return "RegisterServer"
	case ServiceRegisterServer2:
		return "RegisterServer2"
	case ServiceOpenSecureChannel:
		return "OpenSecureChannel"
	case ServiceCloseSecureChannel:
		return "CloseSecureChannel"
	case ServiceCreateSession:
		return "CreateSession"
	case ServiceActivateSession:
		return "ActivateSession"
	case ServiceCloseSession:
		return "CloseSession"
	case ServiceCancel:
		return "Cancel"
	case ServiceAddNodes:
		return "AddNodes"
	case ServiceAddReferences:
		return "AddReferences"
	case ServiceDeleteNodes:
		return "DeleteNodes"
	case ServiceDeleteReferences:
		return "DeleteReferences"
	case ServiceBrowse:
		return "Browse"
	case ServiceBrowseNext:
		return "BrowseNext"
	case ServiceTranslateBrowsePathsToNodeIds:
		return "TranslateBrowsePathsToNodeIds"
	case ServiceQueryFirst:
		return "QueryFirst"
	case ServiceQueryNext:
		return "QueryNext"
	case ServiceRead:
		return "Read"
	case ServiceHistoryRead:
		return "HistoryRead"
	case ServiceWrite:
		return "Write"
	case ServiceHistoryUpdate:
		return "HistoryUpdate"
	case ServiceCall:
		return "Call"
	case ServiceCreateMonitoredItems:
		return "CreateMonitoredItems"
	case ServiceModifyMonitoredItems:
		return "ModifyMonitoredItems"
	case ServiceSetMonitoringMode:
		return "SetMonitoringMode"
	case ServiceSetTriggering:
		return "SetTriggering"
	case ServiceDeleteMonitoredItems:
		return "DeleteMonitoredItems"
	case ServiceCreateSubscription:
		return "CreateSubscription"
	case ServiceModifySubscription:
		return "ModifySubscription"
	case ServiceSetPublishingMode:
		return "SetPublishingMode"
	case ServicePublish:
		return "Publish"
	case ServiceRepublish:
		return "Republish"
	case ServiceTransferSubscriptions:
		return "TransferSubscriptions"
	case ServiceDeleteSubscriptions:
		return "DeleteSubscriptions"
	default:
		// Check if it's a response (request ID + 3)
		if serviceId > 0 && (serviceId-3)%6 == 0 {
			return getServiceName(serviceId - 3) + "Response"
		}
		return "Unknown"
	}
}

// isRequestService returns true if the service ID represents a request.
// In OPC UA, response service IDs are request ID + 3.
func isRequestService(serviceId uint32) bool {
	// Request service IDs follow a pattern where they're 3 less than response IDs
	// Most request service IDs end in specific patterns
	switch serviceId {
	case ServiceFindServers, ServiceFindServersOnNetwork, ServiceGetEndpoints,
		ServiceRegisterServer, ServiceRegisterServer2, ServiceOpenSecureChannel,
		ServiceCloseSecureChannel, ServiceCreateSession, ServiceActivateSession,
		ServiceCloseSession, ServiceCancel, ServiceAddNodes, ServiceAddReferences,
		ServiceDeleteNodes, ServiceDeleteReferences, ServiceBrowse, ServiceBrowseNext,
		ServiceTranslateBrowsePathsToNodeIds, ServiceQueryFirst, ServiceQueryNext,
		ServiceRead, ServiceHistoryRead, ServiceWrite, ServiceHistoryUpdate, ServiceCall,
		ServiceCreateMonitoredItems, ServiceModifyMonitoredItems, ServiceSetMonitoringMode,
		ServiceSetTriggering, ServiceDeleteMonitoredItems, ServiceCreateSubscription,
		ServiceModifySubscription, ServiceSetPublishingMode, ServicePublish, ServiceRepublish,
		ServiceTransferSubscriptions, ServiceDeleteSubscriptions:
		return true
	}
	return false
}

// getStatusCodeName returns the human-readable name for an OPC UA status code.
func getStatusCodeName(code uint32) string {
	// OPC UA status codes - just the high-order 16 bits indicate the code
	statusCode := code >> 16

	switch statusCode {
	case 0x0000:
		return "Good"
	case 0x0001:
		return "Uncertain"
	case 0x8000:
		return "BadUnexpectedError"
	case 0x8001:
		return "BadInternalError"
	case 0x8002:
		return "BadOutOfMemory"
	case 0x8003:
		return "BadResourceUnavailable"
	case 0x8004:
		return "BadCommunicationError"
	case 0x8005:
		return "BadEncodingError"
	case 0x8006:
		return "BadDecodingError"
	case 0x8007:
		return "BadEncodingLimitsExceeded"
	case 0x8010:
		return "BadUnknownResponse"
	case 0x8011:
		return "BadTimeout"
	case 0x8012:
		return "BadServiceUnsupported"
	case 0x8013:
		return "BadShutdown"
	case 0x8014:
		return "BadServerNotConnected"
	case 0x8015:
		return "BadServerHalted"
	case 0x8016:
		return "BadNothingToDo"
	case 0x8020:
		return "BadSessionIdInvalid"
	case 0x8021:
		return "BadSessionClosed"
	case 0x8022:
		return "BadSessionNotActivated"
	case 0x8030:
		return "BadSecureChannelIdInvalid"
	case 0x8031:
		return "BadSecureChannelClosed"
	case 0x8032:
		return "BadSecureChannelTokenUnknown"
	case 0x8040:
		return "BadCertificateInvalid"
	case 0x8041:
		return "BadCertificateTimeInvalid"
	case 0x8042:
		return "BadCertificateIssuerTimeInvalid"
	case 0x8043:
		return "BadCertificateHostNameInvalid"
	case 0x8044:
		return "BadCertificateUriInvalid"
	case 0x8045:
		return "BadCertificateUseNotAllowed"
	case 0x8050:
		return "BadUserAccessDenied"
	case 0x8051:
		return "BadIdentityTokenInvalid"
	case 0x8052:
		return "BadIdentityTokenRejected"
	case 0x8060:
		return "BadSecurityModeRejected"
	case 0x8061:
		return "BadSecurityPolicyRejected"
	case 0x8070:
		return "BadNodeIdInvalid"
	case 0x8071:
		return "BadNodeIdUnknown"
	case 0x8072:
		return "BadAttributeIdInvalid"
	case 0x8080:
		return "BadWriteNotSupported"
	case 0x8090:
		return "BadNotReadable"
	case 0x80A0:
		return "BadNotWritable"
	default:
		if statusCode&0x8000 != 0 {
			return "Bad"
		} else if statusCode&0x4000 != 0 {
			return "Uncertain"
		}
		return "Good"
	}
}

