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

package socks

import (
	"bytes"
	"encoding/binary"
	"net"
	"sync/atomic"

	"go.uber.org/zap"

	"github.com/dreadl0ck/netcap/decoder/core"
	"github.com/dreadl0ck/netcap/reassembly"
	"github.com/dreadl0ck/netcap/types"
)

// SOCKS versions
const (
	SOCKS4  = 0x04
	SOCKS4A = 0x04 // Same version byte, distinguished by null IP
	SOCKS5  = 0x05
)

// SOCKS5 commands
const (
	CmdConnect      = 0x01
	CmdBind         = 0x02
	CmdUDPAssociate = 0x03
)

// SOCKS5 address types
const (
	AddrTypeIPv4   = 0x01
	AddrTypeDomain = 0x03
	AddrTypeIPv6   = 0x04
)

// SOCKS5 authentication methods
const (
	AuthNone         = 0x00
	AuthGSSAPI       = 0x01
	AuthUsernamePass = 0x02
	AuthNoAcceptable = 0xFF
)

type socksReader struct {
	conversation *core.ConversationInfo
}

// New returns a new SOCKS reader.
func (s *socksReader) New(conversation *core.ConversationInfo) core.StreamDecoderInterface {
	return &socksReader{
		conversation: conversation,
	}
}

// Decode parses SOCKS protocol from the stream.
func (s *socksReader) Decode() {
	if Decoder.Writer == nil {
		socksLog.Error("SOCKS Decoder.Writer is nil")
		return
	}

	var clientBuf, serverBuf bytes.Buffer

	for _, d := range s.conversation.Data {
		if d.Direction() == reassembly.TCPDirClientToServer {
			clientBuf.Write(d.Raw())
		} else {
			serverBuf.Write(d.Raw())
		}
	}

	clientData := clientBuf.Bytes()
	serverData := serverBuf.Bytes()

	if len(clientData) == 0 {
		return
	}

	version := clientData[0]

	var msg *types.SOCKS
	switch version {
	case SOCKS5:
		msg = s.parseSOCKS5(clientData, serverData)
	case SOCKS4:
		msg = s.parseSOCKS4(clientData, serverData)
	}

	if msg != nil {
		msg.SrcIP = s.conversation.ClientIP
		msg.DstIP = s.conversation.ServerIP
		msg.SrcPort = int32(s.conversation.ClientPort)
		msg.DstPort = int32(s.conversation.ServerPort)
		msg.CommunityID = s.conversation.CommunityID

		err := Decoder.Writer.Write(msg)
		if err != nil {
			socksLog.Error("failed to write SOCKS record", zap.Error(err))
		} else {
			atomic.AddInt64(&Decoder.NumRecordsWritten, 1)
		}
	}
}

func (s *socksReader) parseSOCKS5(clientData, serverData []byte) *types.SOCKS {
	msg := &types.SOCKS{
		Timestamp: s.conversation.FirstClientPacket.UnixNano(),
		Version:   SOCKS5,
	}

	offset := 0

	// Parse auth methods negotiation (client)
	if len(clientData) < 3 {
		return nil
	}

	numMethods := int(clientData[1])
	offset = 2

	if len(clientData) < offset+numMethods {
		return nil
	}

	for i := 0; i < numMethods; i++ {
		msg.AuthMethods = append(msg.AuthMethods, int32(clientData[offset+i]))
	}
	offset += numMethods
	msg.IsHandshake = true

	// Parse auth method selection (server)
	if len(serverData) >= 2 && serverData[0] == SOCKS5 {
		msg.SelectedAuthMethod = int32(serverData[1])
		msg.AuthMethodName = getAuthMethodName(serverData[1])
	}

	// Look for connection request in remaining client data
	// Skip auth handshake bytes if present
	reqOffset := offset

	// Check if there's username/password auth
	if msg.SelectedAuthMethod == AuthUsernamePass && len(clientData) > reqOffset {
		// Parse username/password authentication
		if clientData[reqOffset] == 0x01 { // Auth version
			reqOffset++
			if reqOffset < len(clientData) {
				userLen := int(clientData[reqOffset])
				reqOffset++
				if reqOffset+userLen <= len(clientData) {
					msg.Username = string(clientData[reqOffset : reqOffset+userLen])
					reqOffset += userLen
					// Skip password
					if reqOffset < len(clientData) {
						passLen := int(clientData[reqOffset])
						reqOffset += 1 + passLen
					}
				}
			}
		}
		// Check auth response in server data (RFC 1929)
		// Auth response format: VER(1) | STATUS(1)
		// VER should be 0x01, STATUS 0x00 = success
		if len(serverData) >= 4 {
			// Find auth response after initial method selection response (2 bytes)
			// Method selection response: VER(1) | METHOD(1)
			authRespOffset := 2
			if authRespOffset+2 <= len(serverData) && serverData[authRespOffset] == 0x01 {
				msg.AuthSuccess = serverData[authRespOffset+1] == 0x00
			}
		}
	} else {
		msg.AuthSuccess = true // No auth required
	}

	// Look for SOCKS5 connection request
	for i := reqOffset; i < len(clientData)-6; i++ {
		if clientData[i] == SOCKS5 && (clientData[i+1] == CmdConnect ||
			clientData[i+1] == CmdBind || clientData[i+1] == CmdUDPAssociate) {
			s.parseSOCKS5Request(msg, clientData[i:])
			msg.IsHandshake = false
			msg.IsRequest = true
			break
		}
	}

	// Parse connection response
	for i := 2; i < len(serverData)-4; i++ {
		if serverData[i] == SOCKS5 {
			s.parseSOCKS5Response(msg, serverData[i:])
			break
		}
	}

	return msg
}

func (s *socksReader) parseSOCKS5Request(msg *types.SOCKS, data []byte) {
	if len(data) < 5 {
		return
	}

	msg.Command = int32(data[1])
	msg.CommandName = getCommandName(data[1])
	// data[2] is reserved
	msg.AddressType = int32(data[3])
	msg.AddressTypeName = getAddressTypeName(data[3])

	offset := 4
	switch data[3] {
	case AddrTypeIPv4:
		if len(data) >= offset+6 {
			msg.DestinationAddress = net.IP(data[offset : offset+4]).String()
			msg.DestinationPort = int32(binary.BigEndian.Uint16(data[offset+4 : offset+6]))
		}
	case AddrTypeDomain:
		if len(data) > offset {
			domainLen := int(data[offset])
			offset++
			if len(data) >= offset+domainLen+2 {
				msg.DestinationAddress = string(data[offset : offset+domainLen])
				msg.DestinationPort = int32(binary.BigEndian.Uint16(data[offset+domainLen : offset+domainLen+2]))
			}
		}
	case AddrTypeIPv6:
		if len(data) >= offset+18 {
			msg.DestinationAddress = net.IP(data[offset : offset+16]).String()
			msg.DestinationPort = int32(binary.BigEndian.Uint16(data[offset+16 : offset+18]))
		}
	}
}

func (s *socksReader) parseSOCKS5Response(msg *types.SOCKS, data []byte) {
	if len(data) < 4 {
		return
	}

	msg.ReplyCode = int32(data[1])
	msg.ReplyCodeName = getSOCKS5ReplyCodeName(data[1])
	msg.ConnectionSuccessful = data[1] == 0x00

	addrType := data[3]
	offset := 4

	switch addrType {
	case AddrTypeIPv4:
		if len(data) >= offset+6 {
			msg.BoundAddress = net.IP(data[offset : offset+4]).String()
			msg.BoundPort = int32(binary.BigEndian.Uint16(data[offset+4 : offset+6]))
		}
	case AddrTypeIPv6:
		if len(data) >= offset+18 {
			msg.BoundAddress = net.IP(data[offset : offset+16]).String()
			msg.BoundPort = int32(binary.BigEndian.Uint16(data[offset+16 : offset+18]))
		}
	}
}

func (s *socksReader) parseSOCKS4(clientData, serverData []byte) *types.SOCKS {
	if len(clientData) < 9 {
		return nil
	}

	msg := &types.SOCKS{
		Timestamp: s.conversation.FirstClientPacket.UnixNano(),
		Version:   SOCKS4,
		IsRequest: true,
	}

	msg.Command = int32(clientData[1])
	msg.CommandName = getCommandName(clientData[1])
	msg.DestinationPort = int32(binary.BigEndian.Uint16(clientData[2:4]))

	ip := net.IP(clientData[4:8])

	// Find null-terminated user ID
	userIDEnd := 8
	for userIDEnd < len(clientData) && clientData[userIDEnd] != 0 {
		userIDEnd++
	}
	if userIDEnd > 8 {
		msg.UserID = string(clientData[8:userIDEnd])
	}

	// Check for SOCKS4a (domain name instead of IP)
	if ip[0] == 0 && ip[1] == 0 && ip[2] == 0 && ip[3] != 0 {
		// SOCKS4a - domain name follows after user ID null terminator
		if userIDEnd+1 < len(clientData) {
			domainEnd := userIDEnd + 1
			for domainEnd < len(clientData) && clientData[domainEnd] != 0 {
				domainEnd++
			}
			msg.DestinationAddress = string(clientData[userIDEnd+1 : domainEnd])
		}
		msg.AddressType = AddrTypeDomain
		msg.AddressTypeName = "Domain"
	} else {
		msg.DestinationAddress = ip.String()
		msg.AddressType = AddrTypeIPv4
		msg.AddressTypeName = "IPv4"
	}

	// Parse SOCKS4 response (RFC 1928)
	// Response format: VN(1) | CD(1) | DSTPORT(2) | DSTIP(4)
	// VN should be 0x00 (null byte), CD is the reply code
	if len(serverData) >= 8 {
		// First byte should be 0x00 for valid SOCKS4 response
		if serverData[0] == 0x00 {
			msg.ReplyCode = int32(serverData[1])
			msg.ReplyCodeName = getSOCKS4ReplyCodeName(serverData[1])
			msg.ConnectionSuccessful = serverData[1] == 0x5A
			msg.BoundPort = int32(binary.BigEndian.Uint16(serverData[2:4]))
			msg.BoundAddress = net.IP(serverData[4:8]).String()
		}
	}

	return msg
}

func getCommandName(cmd uint8) string {
	switch cmd {
	case CmdConnect:
		return "CONNECT"
	case CmdBind:
		return "BIND"
	case CmdUDPAssociate:
		return "UDP ASSOCIATE"
	default:
		return "UNKNOWN"
	}
}

func getAddressTypeName(addrType uint8) string {
	switch addrType {
	case AddrTypeIPv4:
		return "IPv4"
	case AddrTypeDomain:
		return "Domain"
	case AddrTypeIPv6:
		return "IPv6"
	default:
		return "UNKNOWN"
	}
}

func getAuthMethodName(method uint8) string {
	switch method {
	case AuthNone:
		return "No Authentication"
	case AuthGSSAPI:
		return "GSSAPI"
	case AuthUsernamePass:
		return "Username/Password"
	case AuthNoAcceptable:
		return "No Acceptable Methods"
	default:
		return "Unknown"
	}
}

func getSOCKS5ReplyCodeName(code uint8) string {
	switch code {
	case 0x00:
		return "Succeeded"
	case 0x01:
		return "General SOCKS server failure"
	case 0x02:
		return "Connection not allowed by ruleset"
	case 0x03:
		return "Network unreachable"
	case 0x04:
		return "Host unreachable"
	case 0x05:
		return "Connection refused"
	case 0x06:
		return "TTL expired"
	case 0x07:
		return "Command not supported"
	case 0x08:
		return "Address type not supported"
	default:
		return "Unknown"
	}
}

func getSOCKS4ReplyCodeName(code uint8) string {
	switch code {
	case 0x5A:
		return "Request granted"
	case 0x5B:
		return "Request rejected or failed"
	case 0x5C:
		return "Request failed - client not running identd"
	case 0x5D:
		return "Request failed - client identd could not confirm"
	default:
		return "Unknown"
	}
}
