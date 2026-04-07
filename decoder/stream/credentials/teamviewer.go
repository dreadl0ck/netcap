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

const serviceRemoteDesktop = "TeamViewer"

// TeamViewer default port
const remoteDesktopPort = 5938

// TeamViewer protocol magic bytes
const (
	rdMagicV1 = 0x1724
	rdMagicV2 = 0x1130
)

// TeamViewer command codes (security-relevant subset)
var rdCommandNames = map[uint8]string{
	// Identity and Connection
	10: "IDENTIFY",
	11: "REQUEST_CONNECT",
	13: "DISCONNECT",
	14: "VNC_DISCONNECT",
	15: "CONNECTION_FAILED",

	// Keep-alive and session management
	16: "PING",
	17: "PING_OK",
	25: "TIMEOUT",
	27: "KEEPALIVE_BEEP",
	28: "REQUEST_KEEPALIVE",
	35: "KEEPALIVE_REQUEST",
	40: "REQUEST_KEEPALIVE_V2",

	// Master/control commands
	18: "MASTER_COMMAND",
	19: "MASTER_RESPONSE",
	29: "MASTER_COMMAND_ENC",
	30: "MASTER_RESPONSE_ENC",
	45: "NEW_MASTER_LOGIN",
	48: "NEW_MASTER_LOGIN_ANSWER",

	// Session control
	20: "CHANGE_CONNECTION",
	21: "NO_PARTNER_CONNECT",
	22: "CONNECT_TO_WAITING_THREAD",
	23: "SESSION_MODE",
	24: "REQUEST_ROUTING_SESSION",
	31: "REQUEST_RECONNECT",
	32: "RECONNECT_TO_WAITING_THREAD",
	47: "ACCEPT_ROUTING_SESSION",
	53: "END_SESSION",
	54: "SESSION_ID",
	55: "RECONNECT_TO_SESSION",
	56: "RECONNECT_TO_SESSION_ANSWER",

	// Authentication (security-critical)
	102: "AUTH_CHALLENGE",
	103: "AUTH_RESPONSE",
	104: "AUTH_RESULT",

	// Data transfer
	90:  "DATA",
	91:  "DATA_V2",
	92:  "DATA_ENCRYPTED",
	93:  "REQUEST_ENCRYPTION",
	94:  "CONFIRM_ENCRYPTION",
	95:  "ENCRYPTION_REQUEST_FAILED",
	96:  "REQUEST_NO_ENCRYPTION",
	98:  "DATA_V3",
	99:  "DATA_V3_ENCRYPTED",
	106: "DATA_V4",
	107: "DATASTREAM",

	// UDP-specific
	70: "UDP_REQUEST_CONNECT",
	71: "UDP_PING",
	72: "UDP_REQUEST_CONNECT_VPN",
	97: "UDP_FLOW_CONTROL",

	// Meeting/collaboration
	57: "MEETING_CONTROL",
	59: "MEETING_AUTHENTICATION",

	// Miscellaneous
	26: "JAVA_CONNECT",
	33: "START_LOGGING",
	34: "SERVER_AVAILABLE",
	36: "OK",
	37: "FAILED",
	46: "BUDDY",
	49: "BUDDY_ENCRYPTED",
	58: "CARRIER_SWITCH",
	60: "ROUTER_CMD",
	61: "PARTNER_RECONNECT",
}

// rdPacket represents a parsed remote desktop protocol packet
type rdPacket struct {
	Magic       uint16
	Version     string
	CommandCode uint8
	CommandName string
	IsAuthEvent bool
}

// parseRemoteDesktopPacket attempts to parse TeamViewer protocol data
func parseRemoteDesktopPacket(data []byte) *rdPacket {
	if len(data) < 4 {
		return nil
	}

	magic := binary.BigEndian.Uint16(data[0:2])

	// Check for known magic bytes
	var version string
	switch magic {
	case rdMagicV1:
		version = "1.x"
	case rdMagicV2:
		version = "2.x"
	default:
		return nil
	}

	// Command code is at offset 3
	cmdCode := data[3]

	cmdName, found := rdCommandNames[cmdCode]
	if !found {
		return nil
	}

	// Determine if this is a security-relevant auth event
	isAuth := cmdCode >= 102 && cmdCode <= 104

	return &rdPacket{
		Magic:       magic,
		Version:     version,
		CommandCode: cmdCode,
		CommandName: cmdName,
		IsAuthEvent: isAuth,
	}
}

// teamviewerHarvesterFunc detects TeamViewer remote access sessions
// This is useful for identifying unauthorized remote access attempts
func teamviewerHarvesterFunc(data []byte, ident string, ts time.Time) *types.Credentials {
	if len(data) < 10 {
		return nil
	}

	// Search for TeamViewer protocol packets in the data
	for i := 0; i < len(data)-4; i++ {
		pkt := parseRemoteDesktopPacket(data[i:])
		if pkt == nil {
			continue
		}

		// Only emit credentials for security-critical events (auth, login, meeting auth)
		// Skip keepalive, ping, and other non-credential protocol messages
		if !isSecurityCriticalCommand(pkt.CommandCode) {
			continue
		}

		notes := fmt.Sprintf("SECURITY: Remote Desktop Auth Event v%s - %s", pkt.Version, pkt.CommandName)

		service := serviceRemoteDesktop
		if pkt.IsAuthEvent {
			service = "TeamViewer Auth"
		}

		return &types.Credentials{
			Timestamp: ts.UnixNano(),
			Service:   service,
			Flow:      ident,
			User:      pkt.CommandName,
			Password:  "",
			Notes:     notes,
		}
	}

	return nil
}

// teamviewerHarvester is the harvester definition for TeamViewer
var teamviewerHarvester = Harvester{
	Name:          "TeamViewer",
	Description:   "TeamViewer Remote Desktop - detects remote access sessions and authentication events",
	HarvesterFunc: teamviewerHarvesterFunc,
}

// Security-focused helper to identify critical events
func isSecurityCriticalCommand(cmdCode uint8) bool {
	criticalCommands := map[uint8]bool{
		102: true, // AUTH_CHALLENGE
		103: true, // AUTH_RESPONSE
		104: true, // AUTH_RESULT
		45:  true, // NEW_MASTER_LOGIN
		48:  true, // NEW_MASTER_LOGIN_ANSWER
		59:  true, // MEETING_AUTHENTICATION
	}
	return criticalCommands[cmdCode]
}

// isSessionControlCommand checks if command is session-related
func isSessionControlCommand(cmdCode uint8) bool {
	sessionCommands := map[uint8]bool{
		11: true, // REQUEST_CONNECT
		13: true, // DISCONNECT
		22: true, // CONNECT_TO_WAITING_THREAD
		23: true, // SESSION_MODE
		53: true, // END_SESSION
		54: true, // SESSION_ID
		55: true, // RECONNECT_TO_SESSION
	}
	return sessionCommands[cmdCode]
}
