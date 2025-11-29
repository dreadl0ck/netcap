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
	"go.uber.org/zap"

	"github.com/dreadl0ck/netcap/decoder"
	decoderconfig "github.com/dreadl0ck/netcap/decoder/config"
	"github.com/dreadl0ck/netcap/decoder/core"
	logging "github.com/dreadl0ck/netcap/internal/logger"
	"github.com/dreadl0ck/netcap/types"
)

var mqttsnLog = zap.NewNop()

const serviceMQTTSN = "MQTTSN"

// MQTT-SN Message Types
const (
	MsgTypeAdvertise     = 0x00 // Gateway advertisement
	MsgTypeSearchGw      = 0x01 // Gateway search request
	MsgTypeGwInfo        = 0x02 // Gateway info response
	MsgTypeConnect       = 0x04 // Connect request
	MsgTypeConnack       = 0x05 // Connect acknowledgment
	MsgTypeWillTopicReq  = 0x06 // Will topic request
	MsgTypeWillTopic     = 0x07 // Will topic
	MsgTypeWillMsgReq    = 0x08 // Will message request
	MsgTypeWillMsg       = 0x09 // Will message
	MsgTypeRegister      = 0x0A // Topic registration request
	MsgTypeRegack        = 0x0B // Topic registration acknowledgment
	MsgTypePublish       = 0x0C // Publish message
	MsgTypePuback        = 0x0D // Publish acknowledgment
	MsgTypePubcomp       = 0x0E // Publish complete (QoS 2)
	MsgTypePubrec        = 0x0F // Publish received (QoS 2)
	MsgTypePubrel        = 0x10 // Publish release (QoS 2)
	MsgTypeSubscribe     = 0x12 // Subscribe request
	MsgTypeSuback        = 0x13 // Subscribe acknowledgment
	MsgTypeUnsubscribe   = 0x14 // Unsubscribe request
	MsgTypeUnsuback      = 0x15 // Unsubscribe acknowledgment
	MsgTypePingreq       = 0x16 // Ping request
	MsgTypePingresp      = 0x17 // Ping response
	MsgTypeDisconnect    = 0x18 // Disconnect
	MsgTypeWillTopicUpd  = 0x1A // Will topic update
	MsgTypeWillTopicResp = 0x1B // Will topic update response
	MsgTypeWillMsgUpd    = 0x1C // Will message update
	MsgTypeWillMsgResp   = 0x1D // Will message update response
	MsgTypeForwarder     = 0xFE // Forwarder encapsulation
)

// Return codes
const (
	ReturnCodeAccepted              = 0x00
	ReturnCodeRejectedCongestion    = 0x01
	ReturnCodeRejectedInvalidTopicId = 0x02
	ReturnCodeRejectedNotSupported  = 0x03
)

// Flag bit positions
const (
	FlagDUP          = 0x80 // Duplicate flag
	FlagQoSMask      = 0x60 // QoS bits (6-5)
	FlagQoSShift     = 5
	FlagRetain       = 0x10 // Retain flag
	FlagWill         = 0x08 // Will flag
	FlagCleanSession = 0x04 // Clean session flag
	FlagTopicIdType  = 0x03 // Topic ID type bits
)

// Minimum message sizes
const (
	minMessageSize = 2 // Length (1) + MsgType (1)
)

// Decoder for protocol analysis and writing audit records to disk.
var Decoder = &decoder.StreamDecoder{
	Type:        types.Type_NC_MQTTSN,
	Name:        serviceMQTTSN,
	Description: "MQTT for Sensor Networks (MQTT-SN) is a publish/subscribe protocol for wireless sensor networks and IoT devices",
	PostInit: func(d *decoder.StreamDecoder) error {
		var err error
		mqttsnLog, _, err = logging.InitZapLogger(
			decoderconfig.Instance.Out,
			"mqttsn",
			decoderconfig.Instance.Debug,
		)
		return err
	},
	CanDecode: func(client, server []byte) bool {
		// MQTT-SN uses UDP, check both client and server data for valid messages
		return canDecodeMQTTSN(client) || canDecodeMQTTSN(server)
	},
	DeInit: func(sd *decoder.StreamDecoder) error {
		return mqttsnLog.Sync()
	},
	Factory: &mqttsnReader{},
	Typ:     core.UDP, // MQTT-SN uses UDP (default port 1883 or 1884)
}

// canDecodeMQTTSN checks if the data looks like an MQTT-SN message.
// MQTT-SN messages have a specific header format with length and message type.
func canDecodeMQTTSN(data []byte) bool {
	if len(data) < minMessageSize {
		return false
	}

	// Parse message length
	msgLen := 0
	offset := 0

	if data[0] == 0x01 {
		// 3-byte length header for messages > 255 bytes
		if len(data) < 4 {
			return false
		}
		msgLen = int(data[1])<<8 | int(data[2])
		offset = 3
	} else {
		// 1-byte length header
		msgLen = int(data[0])
		offset = 1
	}

	// Validate length
	if msgLen < minMessageSize || msgLen > len(data) {
		return false
	}

	// Check message type
	if offset >= len(data) {
		return false
	}
	msgType := data[offset]

	// Check for valid message types
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
	default:
		return false
	}
}

// getMessageTypeName returns the human-readable name for an MQTT-SN message type.
func getMessageTypeName(msgType int32) string {
	switch msgType {
	case MsgTypeAdvertise:
		return "ADVERTISE"
	case MsgTypeSearchGw:
		return "SEARCHGW"
	case MsgTypeGwInfo:
		return "GWINFO"
	case MsgTypeConnect:
		return "CONNECT"
	case MsgTypeConnack:
		return "CONNACK"
	case MsgTypeWillTopicReq:
		return "WILLTOPICREQ"
	case MsgTypeWillTopic:
		return "WILLTOPIC"
	case MsgTypeWillMsgReq:
		return "WILLMSGREQ"
	case MsgTypeWillMsg:
		return "WILLMSG"
	case MsgTypeRegister:
		return "REGISTER"
	case MsgTypeRegack:
		return "REGACK"
	case MsgTypePublish:
		return "PUBLISH"
	case MsgTypePuback:
		return "PUBACK"
	case MsgTypePubcomp:
		return "PUBCOMP"
	case MsgTypePubrec:
		return "PUBREC"
	case MsgTypePubrel:
		return "PUBREL"
	case MsgTypeSubscribe:
		return "SUBSCRIBE"
	case MsgTypeSuback:
		return "SUBACK"
	case MsgTypeUnsubscribe:
		return "UNSUBSCRIBE"
	case MsgTypeUnsuback:
		return "UNSUBACK"
	case MsgTypePingreq:
		return "PINGREQ"
	case MsgTypePingresp:
		return "PINGRESP"
	case MsgTypeDisconnect:
		return "DISCONNECT"
	case MsgTypeWillTopicUpd:
		return "WILLTOPICUPD"
	case MsgTypeWillTopicResp:
		return "WILLTOPICRESP"
	case MsgTypeWillMsgUpd:
		return "WILLMSGUPD"
	case MsgTypeWillMsgResp:
		return "WILLMSGRESP"
	case MsgTypeForwarder:
		return "FORWARDER"
	default:
		return "UNKNOWN"
	}
}

// getReturnCodeName returns the human-readable name for an MQTT-SN return code.
func getReturnCodeName(code int32) string {
	switch code {
	case ReturnCodeAccepted:
		return "Accepted"
	case ReturnCodeRejectedCongestion:
		return "Rejected: Congestion"
	case ReturnCodeRejectedInvalidTopicId:
		return "Rejected: Invalid Topic ID"
	case ReturnCodeRejectedNotSupported:
		return "Rejected: Not Supported"
	default:
		return "Unknown"
	}
}

// getTopicIdTypeName returns the human-readable name for a topic ID type.
func getTopicIdTypeName(topicIdType int32) string {
	switch topicIdType {
	case 0:
		return "Normal"
	case 1:
		return "Predefined"
	case 2:
		return "Short"
	default:
		return "Reserved"
	}
}

