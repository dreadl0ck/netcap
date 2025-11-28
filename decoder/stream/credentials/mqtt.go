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

package credentials

import (
	"encoding/binary"
	"fmt"
	"time"

	"github.com/dreadl0ck/netcap/types"
)

const serviceMQTT = "MQTT"

// MQTT packet types (first 4 bits of first byte)
const (
	mqttConnect    = 1 << 4 // 0x10
	mqttConnack    = 2 << 4 // 0x20
	mqttPublish    = 3 << 4
	mqttPuback     = 4 << 4
	mqttPubrec     = 5 << 4
	mqttPubrel     = 6 << 4
	mqttPubcomp    = 7 << 4
	mqttSubscribe  = 8 << 4
	mqttSuback     = 9 << 4
	mqttUnsubscribe = 10 << 4
	mqttUnsuback   = 11 << 4
	mqttPingreq    = 12 << 4
	mqttPingresp   = 13 << 4
	mqttDisconnect = 14 << 4
)

// MQTT CONNACK return codes (MQTT 3.1.1)
const (
	mqttConnackAccepted          = 0x00
	mqttConnackRefusedProto      = 0x01
	mqttConnackRefusedClientId   = 0x02
	mqttConnackRefusedServer     = 0x03
	mqttConnackRefusedBadUser    = 0x04
	mqttConnackRefusedNotAuth    = 0x05
)

// MQTT CONNECT flags
const (
	mqttFlagUsername  = 0x80
	mqttFlagPassword  = 0x40
	mqttFlagWillRetain = 0x20
	mqttFlagWillQoS   = 0x18
	mqttFlagWillFlag  = 0x04
	mqttFlagCleanSess = 0x02
)

// mqttHarvesterFunc extracts credentials from MQTT CONNECT packets
// MQTT is used for IoT messaging and supports username/password authentication
func mqttHarvesterFunc(data []byte, ident string, ts time.Time) *types.Credentials {
	if len(data) < 4 {
		return nil
	}

	// Check packet type (first 4 bits)
	packetType := data[0] & 0xF0

	// Handle CONNECT packet (requires at least 10 bytes for minimal valid packet)
	if packetType == mqttConnect {
		if len(data) < 10 {
			return nil
		}
		return parseMQTTConnect(data, ident, ts)
	}

	// Handle CONNACK packet (authentication result) - only 4 bytes needed
	if packetType == mqttConnack {
		return parseMQTTConnack(data, ident, ts)
	}

	return nil
}

// parseMQTTConnect parses an MQTT CONNECT packet to extract credentials
// CONNECT packet format:
// - Fixed header: packet type (1) + remaining length (1-4)
// - Variable header: protocol name + protocol level + connect flags + keep alive
// - Payload: client ID + (will topic + will message) + username + password
func parseMQTTConnect(data []byte, ident string, ts time.Time) *types.Credentials {
	if len(data) < 2 {
		return nil
	}

	// Parse remaining length (variable length encoding)
	remainingLen, lenBytes := decodeMQTTLength(data[1:])
	if remainingLen == 0 || 1+lenBytes+remainingLen > len(data) {
		return nil
	}

	offset := 1 + lenBytes

	// Parse protocol name length (2 bytes)
	if offset+2 > len(data) {
		return nil
	}
	protoNameLen := int(binary.BigEndian.Uint16(data[offset : offset+2]))
	offset += 2

	// Skip protocol name
	if offset+protoNameLen > len(data) {
		return nil
	}
	protoName := string(data[offset : offset+protoNameLen])
	offset += protoNameLen

	// Check for valid MQTT protocol name
	if protoName != "MQTT" && protoName != "MQIsdp" {
		return nil
	}

	// Protocol level (1 byte) - MQTT 3.1.1 is 4, MQTT 5.0 is 5
	if offset+1 > len(data) {
		return nil
	}
	protoLevel := data[offset]
	offset++

	// Connect flags (1 byte)
	if offset+1 > len(data) {
		return nil
	}
	connectFlags := data[offset]
	offset++

	// Keep alive (2 bytes)
	if offset+2 > len(data) {
		return nil
	}
	// keepAlive := binary.BigEndian.Uint16(data[offset : offset+2])
	offset += 2

	// MQTT 5.0 has properties section here
	if protoLevel == 5 {
		if offset >= len(data) {
			return nil
		}
		propsLen, propsLenBytes := decodeMQTTLength(data[offset:])
		if propsLenBytes == 0 || offset+propsLenBytes+propsLen > len(data) {
			return nil
		}
		offset += propsLenBytes + propsLen
	}

	// Parse payload: client ID
	if offset+2 > len(data) {
		return nil
	}
	clientIDLen := int(binary.BigEndian.Uint16(data[offset : offset+2]))
	offset += 2

	if offset+clientIDLen > len(data) {
		return nil
	}
	clientID := string(data[offset : offset+clientIDLen])
	offset += clientIDLen

	// Skip will topic and will message if present
	if connectFlags&mqttFlagWillFlag != 0 {
		// MQTT 5.0 has will properties
		if protoLevel == 5 {
			if offset >= len(data) {
				return nil
			}
			willPropsLen, willPropsLenBytes := decodeMQTTLength(data[offset:])
			if willPropsLenBytes == 0 || offset+willPropsLenBytes+willPropsLen > len(data) {
				return nil
			}
			offset += willPropsLenBytes + willPropsLen
		}

		// Will topic
		if offset+2 > len(data) {
			return nil
		}
		willTopicLen := int(binary.BigEndian.Uint16(data[offset : offset+2]))
		if offset+2+willTopicLen > len(data) {
			return nil
		}
		offset += 2 + willTopicLen

		// Will message
		if offset+2 > len(data) {
			return nil
		}
		willMsgLen := int(binary.BigEndian.Uint16(data[offset : offset+2]))
		if offset+2+willMsgLen > len(data) {
			return nil
		}
		offset += 2 + willMsgLen
	}

	var username, password string

	// Parse username if flag is set
	if connectFlags&mqttFlagUsername != 0 {
		if offset+2 > len(data) {
			return nil
		}
		usernameLen := int(binary.BigEndian.Uint16(data[offset : offset+2]))
		offset += 2

		if offset+usernameLen > len(data) {
			return nil
		}
		username = string(data[offset : offset+usernameLen])
		offset += usernameLen
	}

	// Parse password if flag is set
	if connectFlags&mqttFlagPassword != 0 {
		if offset+2 > len(data) {
			return nil
		}
		passwordLen := int(binary.BigEndian.Uint16(data[offset : offset+2]))
		offset += 2

		if offset+passwordLen > len(data) {
			return nil
		}
		password = string(data[offset : offset+passwordLen])
	}

	// Only return credentials if we have username or password
	if username == "" && password == "" {
		return nil
	}

	mqttVersion := "3.1.1"
	if protoLevel == 5 {
		mqttVersion = "5.0"
	} else if protoLevel == 3 {
		mqttVersion = "3.1"
	}

	return &types.Credentials{
		Timestamp: ts.UnixNano(),
		Service:   serviceMQTT,
		Flow:      ident,
		User:      username,
		Password:  password,
		Notes:     fmt.Sprintf("MQTT %s CONNECT, ClientID: %s", mqttVersion, clientID),
	}
}

// parseMQTTConnack parses an MQTT CONNACK packet for authentication result
// CONNACK format: fixed header + session present flag (1) + return code (1)
func parseMQTTConnack(data []byte, ident string, ts time.Time) *types.Credentials {
	if len(data) < 4 {
		return nil
	}

	// Parse remaining length
	remainingLen, lenBytes := decodeMQTTLength(data[1:])
	if remainingLen < 2 || 1+lenBytes+remainingLen > len(data) {
		return nil
	}

	offset := 1 + lenBytes

	// Skip session present flag
	offset++

	// Return code
	returnCode := data[offset]

	var authSuccess bool
	var authSuccessSet bool
	var notes string

	switch returnCode {
	case mqttConnackAccepted:
		authSuccess = true
		authSuccessSet = true
		notes = "MQTT CONNACK: Connection Accepted"
	case mqttConnackRefusedBadUser:
		authSuccess = false
		authSuccessSet = true
		notes = "MQTT CONNACK: Bad username or password"
	case mqttConnackRefusedNotAuth:
		authSuccess = false
		authSuccessSet = true
		notes = "MQTT CONNACK: Not authorized"
	case mqttConnackRefusedProto:
		notes = "MQTT CONNACK: Unacceptable protocol version"
	case mqttConnackRefusedClientId:
		notes = "MQTT CONNACK: Client identifier rejected"
	case mqttConnackRefusedServer:
		notes = "MQTT CONNACK: Server unavailable"
	default:
		notes = fmt.Sprintf("MQTT CONNACK: Return code %d", returnCode)
	}

	// Only return credentials record for auth-related responses
	if !authSuccessSet {
		return nil
	}

	return &types.Credentials{
		Timestamp:      ts.UnixNano(),
		Service:        serviceMQTT,
		Flow:           ident,
		Notes:          notes,
		AuthSuccess:    authSuccess,
		AuthSuccessSet: authSuccessSet,
	}
}

// decodeMQTTLength decodes MQTT variable length encoding
// Returns (length, bytesRead)
func decodeMQTTLength(data []byte) (int, int) {
	multiplier := 1
	value := 0
	bytesRead := 0

	for i := 0; i < len(data) && i < 4; i++ {
		bytesRead++
		encodedByte := data[i]
		value += int(encodedByte&127) * multiplier

		if encodedByte&128 == 0 {
			break
		}
		multiplier *= 128
	}

	return value, bytesRead
}

// mqttHarvester is the harvester definition for MQTT
var mqttHarvester = Harvester{
	Name:          "MQTT",
	Description:   "Message Queuing Telemetry Transport - captures IoT messaging authentication credentials",
	HarvesterFunc: mqttHarvesterFunc,
}

