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

package types

import (
	"encoding/hex"
	"strconv"
	"strings"
	"time"

	"github.com/dreadl0ck/netcap/encoder"
	"github.com/prometheus/client_golang/prometheus"
)

const (
	fieldMQTTSNLength          = "Length"
	fieldMQTTSNMessageType     = "MessageType"
	fieldMQTTSNMessageTypeName = "MessageTypeName"
	fieldMQTTSNGatewayId       = "GatewayId"
	fieldMQTTSNDuration        = "Duration"
	fieldMQTTSNRadius          = "Radius"
	fieldMQTTSNFlags           = "Flags"
	fieldMQTTSNProtocolId      = "ProtocolId"
	fieldMQTTSNClientId        = "ClientId"
	fieldMQTTSNReturnCode      = "ReturnCode"
	fieldMQTTSNReturnCodeName  = "ReturnCodeName"
	fieldMQTTSNWillTopic       = "WillTopic"
	fieldMQTTSNWillQoS         = "WillQoS"
	fieldMQTTSNWillRetain      = "WillRetain"
	fieldMQTTSNTopicId         = "TopicId"
	fieldMQTTSNMessageId       = "MessageId"
	fieldMQTTSNTopicName       = "TopicName"
	fieldMQTTSNQoS             = "QoS"
	fieldMQTTSNRetain          = "Retain"
	fieldMQTTSNDUP             = "DUP"
	fieldMQTTSNTopicIdType     = "TopicIdType"
	fieldMQTTSNSleepDuration   = "SleepDuration"
	fieldMQTTSNCtrl            = "Ctrl"
	fieldMQTTSNWirelessNodeId  = "WirelessNodeId"
	fieldMQTTSNCleanSession    = "CleanSession"
	fieldMQTTSNWill            = "Will"
	fieldMQTTSNTopicIdTypeName = "TopicIdTypeName"
)

var fieldsMQTTSN = []string{
	fieldTimestamp,
	fieldSrcIP,
	fieldDstIP,
	fieldSrcPort,
	fieldDstPort,
	fieldMQTTSNLength,
	fieldMQTTSNMessageType,
	fieldMQTTSNMessageTypeName,
	fieldMQTTSNGatewayId,
	fieldMQTTSNDuration,
	fieldMQTTSNRadius,
	fieldMQTTSNFlags,
	fieldMQTTSNProtocolId,
	fieldMQTTSNClientId,
	fieldMQTTSNReturnCode,
	fieldMQTTSNReturnCodeName,
	fieldMQTTSNWillTopic,
	fieldMQTTSNWillQoS,
	fieldMQTTSNWillRetain,
	fieldMQTTSNTopicId,
	fieldMQTTSNMessageId,
	fieldMQTTSNTopicName,
	fieldMQTTSNQoS,
	fieldMQTTSNRetain,
	fieldMQTTSNDUP,
	fieldMQTTSNTopicIdType,
	fieldMQTTSNSleepDuration,
	fieldMQTTSNCtrl,
	fieldMQTTSNWirelessNodeId,
	fieldMQTTSNCleanSession,
	fieldMQTTSNWill,
	fieldMQTTSNTopicIdTypeName,
}

// CSVHeader returns the CSV header for the audit record.
func (m *MQTTSN) CSVHeader() []string {
	return filter(fieldsMQTTSN)
}

// CSVRecord returns the CSV record for the audit record.
func (m *MQTTSN) CSVRecord() []string {
	return filter([]string{
		formatTimestamp(m.Timestamp),
		m.SrcIP,
		m.DstIP,
		formatInt32(m.SrcPort),
		formatInt32(m.DstPort),
		formatInt32(m.Length),
		formatInt32(m.MessageType),
		m.MessageTypeName,
		formatInt32(m.GatewayId),
		formatInt32(m.Duration),
		formatInt32(m.Radius),
		formatInt32(m.Flags),
		formatInt32(m.ProtocolId),
		m.ClientId,
		formatInt32(m.ReturnCode),
		m.ReturnCodeName,
		m.WillTopic,
		formatInt32(m.WillQoS),
		strconv.FormatBool(m.WillRetain),
		formatInt32(m.TopicId),
		formatInt32(m.MessageId),
		m.TopicName,
		formatInt32(m.QoS),
		strconv.FormatBool(m.Retain),
		strconv.FormatBool(m.DUP),
		formatInt32(m.TopicIdType),
		formatInt32(m.SleepDuration),
		formatInt32(m.Ctrl),
		m.WirelessNodeId,
		strconv.FormatBool(m.CleanSession),
		strconv.FormatBool(m.Will),
		m.TopicIdTypeName,
	})
}

// Time returns the timestamp associated with the audit record.
func (m *MQTTSN) Time() int64 {
	return m.Timestamp
}

// JSON returns the JSON representation of the audit record.
func (m *MQTTSN) JSON() (string, error) {
	// convert unix timestamp from nano to millisecond precision for elastic
	m.Timestamp /= int64(time.Millisecond)

	return jsonMarshaler.MarshalToString(m)
}

var mqttsnMetric = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: strings.ToLower(Type_NC_MQTTSN.String()),
		Help: Type_NC_MQTTSN.String() + " audit records",
	},
	fieldsMQTTSN[1:],
)

// Inc increments the metrics for the audit record.
func (m *MQTTSN) Inc() {
	mqttsnMetric.WithLabelValues(m.CSVRecord()[1:]...).Inc()
}

// SetPacketContext sets the associated packet context for the audit record.
func (m *MQTTSN) SetPacketContext(ctx *PacketContext) {
	m.SrcIP = ctx.SrcIP
	m.DstIP = ctx.DstIP
	m.SrcPort = ctx.SrcPort
	m.DstPort = ctx.DstPort
}

// Src returns the source address of the audit record.
func (m *MQTTSN) Src() string {
	return m.SrcIP
}

// Dst returns the destination address of the audit record.
func (m *MQTTSN) Dst() string {
	return m.DstIP
}

var mqttsnEncoder = encoder.NewValueEncoder()

// Encode will encode categorical values and normalize according to configuration.
func (m *MQTTSN) Encode() []string {
	return filter([]string{
		mqttsnEncoder.Int64(fieldTimestamp, m.Timestamp),
		mqttsnEncoder.String(fieldSrcIP, m.SrcIP),
		mqttsnEncoder.String(fieldDstIP, m.DstIP),
		mqttsnEncoder.Int32(fieldSrcPort, m.SrcPort),
		mqttsnEncoder.Int32(fieldDstPort, m.DstPort),
		mqttsnEncoder.Int32(fieldMQTTSNLength, m.Length),
		mqttsnEncoder.Int32(fieldMQTTSNMessageType, m.MessageType),
		mqttsnEncoder.String(fieldMQTTSNMessageTypeName, m.MessageTypeName),
		mqttsnEncoder.Int32(fieldMQTTSNGatewayId, m.GatewayId),
		mqttsnEncoder.Int32(fieldMQTTSNDuration, m.Duration),
		mqttsnEncoder.Int32(fieldMQTTSNRadius, m.Radius),
		mqttsnEncoder.Int32(fieldMQTTSNFlags, m.Flags),
		mqttsnEncoder.Int32(fieldMQTTSNProtocolId, m.ProtocolId),
		mqttsnEncoder.String(fieldMQTTSNClientId, m.ClientId),
		mqttsnEncoder.Int32(fieldMQTTSNReturnCode, m.ReturnCode),
		mqttsnEncoder.String(fieldMQTTSNReturnCodeName, m.ReturnCodeName),
		mqttsnEncoder.String(fieldMQTTSNWillTopic, m.WillTopic),
		mqttsnEncoder.Int32(fieldMQTTSNWillQoS, m.WillQoS),
		mqttsnEncoder.Bool(m.WillRetain),
		mqttsnEncoder.Int32(fieldMQTTSNTopicId, m.TopicId),
		mqttsnEncoder.Int32(fieldMQTTSNMessageId, m.MessageId),
		mqttsnEncoder.String(fieldMQTTSNTopicName, m.TopicName),
		mqttsnEncoder.Int32(fieldMQTTSNQoS, m.QoS),
		mqttsnEncoder.Bool(m.Retain),
		mqttsnEncoder.Bool(m.DUP),
		mqttsnEncoder.Int32(fieldMQTTSNTopicIdType, m.TopicIdType),
		mqttsnEncoder.Int32(fieldMQTTSNSleepDuration, m.SleepDuration),
		mqttsnEncoder.Int32(fieldMQTTSNCtrl, m.Ctrl),
		mqttsnEncoder.String(fieldMQTTSNWirelessNodeId, m.WirelessNodeId),
		mqttsnEncoder.Bool(m.CleanSession),
		mqttsnEncoder.Bool(m.Will),
		mqttsnEncoder.String(fieldMQTTSNTopicIdTypeName, m.TopicIdTypeName),
	})
}

// Analyze will invoke the configured analyzer for the audit record and return a score.
func (m *MQTTSN) Analyze() {}

// NetcapType returns the type of the current audit record.
func (m *MQTTSN) NetcapType() Type {
	return Type_NC_MQTTSN
}

// PayloadHex returns the payload as a hex string for display purposes.
func (m *MQTTSN) PayloadHex() string {
	if m.Payload == nil {
		return ""
	}
	return hex.EncodeToString(m.Payload)
}

// WillMessageHex returns the will message as a hex string for display purposes.
func (m *MQTTSN) WillMessageHex() string {
	if m.WillMessage == nil {
		return ""
	}
	return hex.EncodeToString(m.WillMessage)
}

