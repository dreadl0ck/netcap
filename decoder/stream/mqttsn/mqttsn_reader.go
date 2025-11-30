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

package mqttsn

import (
	"bytes"
	"sync/atomic"

	"go.uber.org/zap"

	"github.com/dreadl0ck/netcap/decoder/core"
	"github.com/dreadl0ck/netcap/types"
)

type mqttsnReader struct {
	conversation *core.ConversationInfo
}

// New returns a new MQTT-SN reader.
func (m *mqttsnReader) New(conversation *core.ConversationInfo) core.StreamDecoderInterface {
	return &mqttsnReader{
		conversation: conversation,
	}
}

// Decode parses MQTT-SN messages from the stream.
func (m *mqttsnReader) Decode() {
	if Decoder.Writer == nil {
		mqttsnLog.Error("MQTTSN Decoder.Writer is nil")
		return
	}

	var buf bytes.Buffer

	for _, data := range m.conversation.Data {
		buf.Write(data.Raw())
	}

	frameData := buf.Bytes()
	offset := 0

	for offset < len(frameData) {
		msg, consumed := m.parseMQTTSNMessage(frameData[offset:])
		if msg != nil {
			msg.SrcIP = m.conversation.ClientIP
			msg.DstIP = m.conversation.ServerIP
			msg.SrcPort = int32(m.conversation.ClientPort)
			msg.DstPort = int32(m.conversation.ServerPort)
			msg.CommunityID = m.conversation.CommunityID

			err := Decoder.Writer.Write(msg)
			if err != nil {
				mqttsnLog.Error("failed to write MQTTSN record", zap.Error(err))
			} else {
				atomic.AddInt64(&Decoder.NumRecordsWritten, 1)
			}
		}

		if consumed > 0 {
			offset += consumed
		} else {
			// Skip one byte if we can't parse
			offset++
		}
	}
}

// parseMQTTSNMessage parses an MQTT-SN message and returns the parsed record and bytes consumed.
func (m *mqttsnReader) parseMQTTSNMessage(data []byte) (*types.MQTTSN, int) {
	if len(data) < minMessageSize {
		return nil, 0
	}

	// Parse length field
	msgLen := 0
	headerLen := 0

	if data[0] == 0x01 {
		// 3-byte length header for messages > 255 bytes
		if len(data) < 4 {
			return nil, 0
		}
		msgLen = int(data[1])<<8 | int(data[2])
		headerLen = 3
	} else {
		// 1-byte length header
		msgLen = int(data[0])
		headerLen = 1
	}

	// Validate message length bounds
	// msgLen must be >= headerLen + 1 (header + message type byte)
	// msgLen must be <= available data
	payloadStart := headerLen + 1
	if msgLen < payloadStart || msgLen > len(data) || payloadStart > msgLen {
		return nil, 0
	}

	// Get message type
	msgType := int32(data[headerLen])

	// Verify it's a valid message type
	if !isValidMessageType(msgType) {
		return nil, 0
	}

	msg := &types.MQTTSN{
		Timestamp:       m.conversation.FirstClientPacket.UnixNano(),
		Length:          int32(msgLen),
		MessageType:     msgType,
		MessageTypeName: getMessageTypeName(msgType),
	}

	// Parse message-specific fields - bounds already validated above
	payload := data[payloadStart:msgLen]

	switch msgType {
	case MsgTypeAdvertise:
		m.parseAdvertise(msg, payload)
	case MsgTypeSearchGw:
		m.parseSearchGw(msg, payload)
	case MsgTypeGwInfo:
		m.parseGwInfo(msg, payload)
	case MsgTypeConnect:
		m.parseConnect(msg, payload)
	case MsgTypeConnack:
		m.parseConnack(msg, payload)
	case MsgTypeWillTopic:
		m.parseWillTopic(msg, payload)
	case MsgTypeWillMsg:
		m.parseWillMsg(msg, payload)
	case MsgTypeRegister:
		m.parseRegister(msg, payload)
	case MsgTypeRegack:
		m.parseRegack(msg, payload)
	case MsgTypePublish:
		m.parsePublish(msg, payload)
	case MsgTypePuback:
		m.parsePuback(msg, payload)
	case MsgTypePubcomp, MsgTypePubrec, MsgTypePubrel:
		m.parsePubFlow(msg, payload)
	case MsgTypeSubscribe:
		m.parseSubscribe(msg, payload)
	case MsgTypeSuback:
		m.parseSuback(msg, payload)
	case MsgTypeUnsubscribe:
		m.parseUnsubscribe(msg, payload)
	case MsgTypeUnsuback:
		m.parseUnsuback(msg, payload)
	case MsgTypePingreq:
		m.parsePingreq(msg, payload)
	case MsgTypeDisconnect:
		m.parseDisconnect(msg, payload)
	case MsgTypeWillTopicUpd:
		m.parseWillTopicUpd(msg, payload)
	case MsgTypeWillTopicResp:
		m.parseWillTopicResp(msg, payload)
	case MsgTypeWillMsgUpd:
		m.parseWillMsgUpd(msg, payload)
	case MsgTypeWillMsgResp:
		m.parseWillMsgResp(msg, payload)
	case MsgTypeForwarder:
		m.parseForwarder(msg, data)
	}

	return msg, msgLen
}

func isValidMessageType(msgType int32) bool {
	switch msgType {
	case MsgTypeAdvertise,
		MsgTypeSearchGw,
		MsgTypeGwInfo,
		MsgTypeConnect,
		MsgTypeConnack,
		MsgTypeWillTopicReq,
		MsgTypeWillTopic,
		MsgTypeWillMsgReq,
		MsgTypeWillMsg,
		MsgTypeRegister,
		MsgTypeRegack,
		MsgTypePublish,
		MsgTypePuback,
		MsgTypePubcomp,
		MsgTypePubrec,
		MsgTypePubrel,
		MsgTypeSubscribe,
		MsgTypeSuback,
		MsgTypeUnsubscribe,
		MsgTypeUnsuback,
		MsgTypePingreq,
		MsgTypePingresp,
		MsgTypeDisconnect,
		MsgTypeWillTopicUpd,
		MsgTypeWillTopicResp,
		MsgTypeWillMsgUpd,
		MsgTypeWillMsgResp,
		MsgTypeForwarder:
		return true
	}
	return false
}

// parseAdvertise parses ADVERTISE message
// Format: GwId (1) + Duration (2)
func (m *mqttsnReader) parseAdvertise(msg *types.MQTTSN, payload []byte) {
	if len(payload) < 3 {
		return
	}
	msg.GatewayId = int32(payload[0])
	msg.Duration = int32(payload[1])<<8 | int32(payload[2])
}

// parseSearchGw parses SEARCHGW message
// Format: Radius (1)
func (m *mqttsnReader) parseSearchGw(msg *types.MQTTSN, payload []byte) {
	if len(payload) < 1 {
		return
	}
	msg.Radius = int32(payload[0])
}

// parseGwInfo parses GWINFO message
// Format: GwId (1) + GwAdd (optional, variable)
func (m *mqttsnReader) parseGwInfo(msg *types.MQTTSN, payload []byte) {
	if len(payload) < 1 {
		return
	}
	msg.GatewayId = int32(payload[0])
}

// parseConnect parses CONNECT message
// Format: Flags (1) + ProtocolId (1) + Duration (2) + ClientId (variable)
func (m *mqttsnReader) parseConnect(msg *types.MQTTSN, payload []byte) {
	if len(payload) < 4 {
		return
	}

	flags := payload[0]
	msg.Flags = int32(flags)
	msg.ProtocolId = int32(payload[1])
	msg.Duration = int32(payload[2])<<8 | int32(payload[3])

	// Parse flags
	msg.Will = (flags & FlagWill) != 0
	msg.CleanSession = (flags & FlagCleanSession) != 0

	// ClientId
	if len(payload) > 4 {
		msg.ClientId = string(payload[4:])
	}
}

// parseConnack parses CONNACK message
// Format: ReturnCode (1)
func (m *mqttsnReader) parseConnack(msg *types.MQTTSN, payload []byte) {
	if len(payload) < 1 {
		return
	}
	msg.ReturnCode = int32(payload[0])
	msg.ReturnCodeName = getReturnCodeName(msg.ReturnCode)
}

// parseWillTopic parses WILLTOPIC message
// Format: Flags (1) + WillTopic (variable)
func (m *mqttsnReader) parseWillTopic(msg *types.MQTTSN, payload []byte) {
	if len(payload) < 1 {
		return
	}

	flags := payload[0]
	msg.Flags = int32(flags)
	msg.WillQoS = int32((flags & FlagQoSMask) >> FlagQoSShift)
	msg.WillRetain = (flags & FlagRetain) != 0

	if len(payload) > 1 {
		msg.WillTopic = string(payload[1:])
	}
}

// parseWillMsg parses WILLMSG message
// Format: WillMsg (variable)
func (m *mqttsnReader) parseWillMsg(msg *types.MQTTSN, payload []byte) {
	if len(payload) > 0 {
		msg.WillMessage = payload
	}
}

// parseRegister parses REGISTER message
// Format: TopicId (2) + MsgId (2) + TopicName (variable)
func (m *mqttsnReader) parseRegister(msg *types.MQTTSN, payload []byte) {
	if len(payload) < 4 {
		return
	}
	msg.TopicId = int32(payload[0])<<8 | int32(payload[1])
	msg.MessageId = int32(payload[2])<<8 | int32(payload[3])

	if len(payload) > 4 {
		msg.TopicName = string(payload[4:])
	}
}

// parseRegack parses REGACK message
// Format: TopicId (2) + MsgId (2) + ReturnCode (1)
func (m *mqttsnReader) parseRegack(msg *types.MQTTSN, payload []byte) {
	if len(payload) < 5 {
		return
	}
	msg.TopicId = int32(payload[0])<<8 | int32(payload[1])
	msg.MessageId = int32(payload[2])<<8 | int32(payload[3])
	msg.ReturnCode = int32(payload[4])
	msg.ReturnCodeName = getReturnCodeName(msg.ReturnCode)
}

// parsePublish parses PUBLISH message
// Format: Flags (1) + TopicId (2) + MsgId (2) + Data (variable)
func (m *mqttsnReader) parsePublish(msg *types.MQTTSN, payload []byte) {
	if len(payload) < 5 {
		return
	}

	flags := payload[0]
	msg.Flags = int32(flags)
	msg.DUP = (flags & FlagDUP) != 0
	msg.QoS = int32((flags & FlagQoSMask) >> FlagQoSShift)
	msg.Retain = (flags & FlagRetain) != 0
	msg.TopicIdType = int32(flags & FlagTopicIdType)
	msg.TopicIdTypeName = getTopicIdTypeName(msg.TopicIdType)

	msg.TopicId = int32(payload[1])<<8 | int32(payload[2])
	msg.MessageId = int32(payload[3])<<8 | int32(payload[4])

	if len(payload) > 5 {
		msg.Payload = payload[5:]
	}
}

// parsePuback parses PUBACK message
// Format: TopicId (2) + MsgId (2) + ReturnCode (1)
func (m *mqttsnReader) parsePuback(msg *types.MQTTSN, payload []byte) {
	if len(payload) < 5 {
		return
	}
	msg.TopicId = int32(payload[0])<<8 | int32(payload[1])
	msg.MessageId = int32(payload[2])<<8 | int32(payload[3])
	msg.ReturnCode = int32(payload[4])
	msg.ReturnCodeName = getReturnCodeName(msg.ReturnCode)
}

// parsePubFlow parses PUBCOMP, PUBREC, PUBREL messages
// Format: MsgId (2)
func (m *mqttsnReader) parsePubFlow(msg *types.MQTTSN, payload []byte) {
	if len(payload) < 2 {
		return
	}
	msg.MessageId = int32(payload[0])<<8 | int32(payload[1])
}

// parseSubscribe parses SUBSCRIBE message
// Format: Flags (1) + MsgId (2) + TopicId/TopicName (variable)
func (m *mqttsnReader) parseSubscribe(msg *types.MQTTSN, payload []byte) {
	if len(payload) < 3 {
		return
	}

	flags := payload[0]
	msg.Flags = int32(flags)
	msg.DUP = (flags & FlagDUP) != 0
	msg.QoS = int32((flags & FlagQoSMask) >> FlagQoSShift)
	msg.TopicIdType = int32(flags & FlagTopicIdType)
	msg.TopicIdTypeName = getTopicIdTypeName(msg.TopicIdType)

	msg.MessageId = int32(payload[1])<<8 | int32(payload[2])

	if len(payload) > 3 {
		switch msg.TopicIdType {
		case 0: // Normal topic name
			msg.TopicName = string(payload[3:])
		case 1, 2: // Predefined or short topic
			if len(payload) >= 5 {
				msg.TopicId = int32(payload[3])<<8 | int32(payload[4])
			}
		}
	}
}

// parseSuback parses SUBACK message
// Format: Flags (1) + TopicId (2) + MsgId (2) + ReturnCode (1)
func (m *mqttsnReader) parseSuback(msg *types.MQTTSN, payload []byte) {
	if len(payload) < 6 {
		return
	}

	flags := payload[0]
	msg.Flags = int32(flags)
	msg.QoS = int32((flags & FlagQoSMask) >> FlagQoSShift)

	msg.TopicId = int32(payload[1])<<8 | int32(payload[2])
	msg.MessageId = int32(payload[3])<<8 | int32(payload[4])
	msg.ReturnCode = int32(payload[5])
	msg.ReturnCodeName = getReturnCodeName(msg.ReturnCode)
}

// parseUnsubscribe parses UNSUBSCRIBE message
// Format: Flags (1) + MsgId (2) + TopicId/TopicName (variable)
func (m *mqttsnReader) parseUnsubscribe(msg *types.MQTTSN, payload []byte) {
	if len(payload) < 3 {
		return
	}

	flags := payload[0]
	msg.Flags = int32(flags)
	msg.TopicIdType = int32(flags & FlagTopicIdType)
	msg.TopicIdTypeName = getTopicIdTypeName(msg.TopicIdType)

	msg.MessageId = int32(payload[1])<<8 | int32(payload[2])

	if len(payload) > 3 {
		switch msg.TopicIdType {
		case 0: // Normal topic name
			msg.TopicName = string(payload[3:])
		case 1, 2: // Predefined or short topic
			if len(payload) >= 5 {
				msg.TopicId = int32(payload[3])<<8 | int32(payload[4])
			}
		}
	}
}

// parseUnsuback parses UNSUBACK message
// Format: MsgId (2)
func (m *mqttsnReader) parseUnsuback(msg *types.MQTTSN, payload []byte) {
	if len(payload) < 2 {
		return
	}
	msg.MessageId = int32(payload[0])<<8 | int32(payload[1])
}

// parsePingreq parses PINGREQ message
// Format: ClientId (optional, variable) - only for sleeping clients
func (m *mqttsnReader) parsePingreq(msg *types.MQTTSN, payload []byte) {
	if len(payload) > 0 {
		msg.ClientId = string(payload)
	}
}

// parseDisconnect parses DISCONNECT message
// Format: Duration (optional, 2) - for sleeping clients
func (m *mqttsnReader) parseDisconnect(msg *types.MQTTSN, payload []byte) {
	if len(payload) >= 2 {
		msg.SleepDuration = int32(payload[0])<<8 | int32(payload[1])
	}
}

// parseWillTopicUpd parses WILLTOPICUPD message
// Format: Flags (1) + WillTopic (variable)
func (m *mqttsnReader) parseWillTopicUpd(msg *types.MQTTSN, payload []byte) {
	if len(payload) < 1 {
		// Empty WillTopic means delete
		return
	}

	flags := payload[0]
	msg.Flags = int32(flags)
	msg.WillQoS = int32((flags & FlagQoSMask) >> FlagQoSShift)
	msg.WillRetain = (flags & FlagRetain) != 0

	if len(payload) > 1 {
		msg.WillTopic = string(payload[1:])
	}
}

// parseWillTopicResp parses WILLTOPICRESP message
// Format: ReturnCode (1)
func (m *mqttsnReader) parseWillTopicResp(msg *types.MQTTSN, payload []byte) {
	if len(payload) < 1 {
		return
	}
	msg.ReturnCode = int32(payload[0])
	msg.ReturnCodeName = getReturnCodeName(msg.ReturnCode)
}

// parseWillMsgUpd parses WILLMSGUPD message
// Format: WillMsg (variable)
func (m *mqttsnReader) parseWillMsgUpd(msg *types.MQTTSN, payload []byte) {
	if len(payload) > 0 {
		msg.WillMessage = payload
	}
}

// parseWillMsgResp parses WILLMSGRESP message
// Format: ReturnCode (1)
func (m *mqttsnReader) parseWillMsgResp(msg *types.MQTTSN, payload []byte) {
	if len(payload) < 1 {
		return
	}
	msg.ReturnCode = int32(payload[0])
	msg.ReturnCodeName = getReturnCodeName(msg.ReturnCode)
}

// parseForwarder parses FORWARDER encapsulation message
// Format: Ctrl (1) + WirelessNodeId (variable) + Encapsulated MQTT-SN message
func (m *mqttsnReader) parseForwarder(msg *types.MQTTSN, data []byte) {
	// Forwarder messages have a different structure
	// Length (1 or 3) + MsgType (1) + Ctrl (1) + WirelessNodeId (variable) + MQTTSN msg
	if len(data) < 4 {
		return
	}

	offset := 1 // Skip length byte
	if data[0] == 0x01 {
		offset = 3 // 3-byte length header
	}

	if offset+1 >= len(data) {
		return
	}

	// Skip message type (already parsed)
	offset++

	// Ctrl field
	msg.Ctrl = int32(data[offset])
	offset++

	// For now, just note we have a forwarder message
	// The WirelessNodeId and encapsulated message would need more parsing
	if offset < len(data) {
		// Remaining data contains WirelessNodeId and encapsulated message
		// This is implementation-specific based on the wireless network
		remaining := data[offset:]
		if len(remaining) > 0 {
			// First few bytes could be the wireless node ID
			// This is typically 1-8 bytes depending on the network
			nodeIdLen := len(remaining)
			if nodeIdLen > 8 {
				nodeIdLen = 8
			}
			msg.WirelessNodeId = string(remaining[:nodeIdLen])
		}
	}
}

