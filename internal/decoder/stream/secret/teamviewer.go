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

package secret

import (
	"encoding/binary"
	"fmt"
	"time"

	"github.com/dreadl0ck/netcap/internal/decoder/core"
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
	63: "ACK",
}

// rdPacket represents a parsed remote desktop protocol packet
type rdPacket struct {
	Magic       uint16
	Version     string
	CommandCode uint8
	CommandName string
	IsAuthEvent bool
	Size        int
	Payload     []byte
}

// parseRemoteDesktopPacket attempts to parse TeamViewer protocol data
func parseRemoteDesktopPacket(data []byte) *rdPacket {
	if len(data) < 5 {
		return nil
	}

	magic := binary.BigEndian.Uint16(data[0:2])

	// Command1: magic(2), command(1), LE length(2), payload.
	// Command2: magic(2), command(1), flags(1), LE length(4),
	// packet/request/class/header-offset(4 each), payload.
	// See random-wireshark-dissectors@3896597a/teamviewer.lua.
	var version string
	header, length := 5, 0
	switch magic {
	case rdMagicV1:
		version = "command1"
		length = int(binary.LittleEndian.Uint16(data[3:5]))
	case rdMagicV2:
		if len(data) < 24 || data[3] != 0 || binary.LittleEndian.Uint32(data[20:24]) != 24 {
			return nil
		}
		version, header = "command2", 24
		length = int(binary.LittleEndian.Uint32(data[4:8]))
	default:
		return nil
	}

	if length > 1<<20 || length > len(data)-header {
		return nil
	}
	cmdCode := data[2]

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
		Size:        header + length,
		Payload:     data[header : header+length],
	}
}

// teamviewerHarvesterFunc detects TeamViewer remote access sessions
// This is useful for identifying unauthorized remote access attempts
func teamviewerHarvesterFunc(data []byte, ident string, ts time.Time) *types.Secret {
	for len(data) > 0 {
		pkt := parseRemoteDesktopPacket(data)
		if pkt == nil {
			return nil
		}
		data = data[pkt.Size:]
		if s := teamviewerSecret(pkt, ident, ts.UnixNano()); s != nil {
			return s
		}
	}
	return nil
}

func teamviewerSecret(pkt *rdPacket, ident string, at int64) *types.Secret {
	if !isSecurityCriticalCommand(pkt.CommandCode) {
		return nil
	}
	// Authentication is not a header-only event. Challenge/response carry
	// opaque proof material; result/login messages carry at least a word.
	minimum := 4
	if pkt.CommandCode == 102 || pkt.CommandCode == 103 {
		minimum = 16
	}
	if len(pkt.Payload) < minimum {
		return nil
	}

	notes := fmt.Sprintf("Remote Desktop Auth Event (%s) - %s; encrypted/opaque authentication material", pkt.Version, pkt.CommandName)

	service := serviceRemoteDesktop
	if pkt.IsAuthEvent {
		service = "TeamViewer Auth"
	}

	return &types.Secret{
		Timestamp: at,
		Service:   service,
		Flow:      ident,
		User:      pkt.CommandName,
		Password:  "",
		Notes:     notes,
	}
}

// Per-direction framing preserves split messages without searching unrelated
// payloads or joining bytes across capture loss. UDP encapsulation is not parsed.
func harvestTeamViewerConversation(c *core.ConversationInfo, emit func(*types.Secret)) {
	type side struct {
		data          []byte
		at            int64
		seen, stopped bool
	}
	var sides [2]side
	for _, f := range c.Data {
		i := 0
		if core.FromServer(f) {
			i = 1
		}
		s := &sides[i]
		if s.stopped {
			continue
		}
		if d, ok := f.(*core.StreamData); ok && (d.DiscardedBytes > 0 || d.SkippedBytes != 0 && (d.SkippedBytes > 0 || s.seen)) {
			s.stopped, s.data = true, nil
			continue
		}
		s.seen = true
		data := f.Raw()
		for len(data) > 0 {
			if len(s.data) == 0 {
				s.at = core.FragmentTime(f)
			}
			target := 5
			if len(s.data) >= 5 {
				switch binary.BigEndian.Uint16(s.data) {
				case rdMagicV1:
					target += int(binary.LittleEndian.Uint16(s.data[3:5]))
				case rdMagicV2:
					target = 24
					if len(s.data) >= 24 {
						target += int(binary.LittleEndian.Uint32(s.data[4:8]))
					}
				default:
					s.stopped = true
				}
			}
			if target > (1<<20)+24 || s.stopped {
				s.stopped, s.data = true, nil
				break
			}
			n := min(target-len(s.data), len(data))
			s.data = append(s.data, data[:n]...)
			data = data[n:]
			if len(s.data) < target {
				break
			}
			// First fill the fixed header; then its declared payload.
			if target == 5 && len(s.data) == 5 && (s.data[0] == 0x11 || binary.LittleEndian.Uint16(s.data[3:5]) != 0) {
				continue
			}
			if target == 24 && s.data[0] == 0x11 && binary.LittleEndian.Uint32(s.data[4:8]) != 0 {
				continue
			}
			pkt := parseRemoteDesktopPacket(s.data)
			if pkt == nil {
				s.stopped, s.data = true, nil
				break
			}
			if secret := teamviewerSecret(pkt, c.Ident, s.at); secret != nil {
				secret.CommunityID = c.CommunityID
				emit(secret)
			}
			s.data = s.data[:0]
		}
	}
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
