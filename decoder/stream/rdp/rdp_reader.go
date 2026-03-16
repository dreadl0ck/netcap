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

package rdp

import (
	"bytes"
	"encoding/binary"
	"regexp"
	"strings"
	"sync/atomic"

	"go.uber.org/zap"

	"github.com/dreadl0ck/netcap/decoder/core"
	"github.com/dreadl0ck/netcap/reassembly"
	"github.com/dreadl0ck/netcap/types"
)

// RDP Protocol constants
const (
	// RDP Negotiation Types
	RDPNegReq     = 0x01
	RDPNegRsp     = 0x02
	RDPNegFailure = 0x03

	// RDP Protocols (bitmask)
	ProtocolRDP      = 0x00000000
	ProtocolSSL      = 0x00000001
	ProtocolHybrid   = 0x00000002 // CredSSP with NLA
	ProtocolRDSTLS   = 0x00000004
	ProtocolHybridEx = 0x00000008 // CredSSP with Early User Auth

	// MCS Connect Initial/Response
	BER_TAG_MCS_CONNECT_INITIAL  = 0x7F65
	BER_TAG_MCS_CONNECT_RESPONSE = 0x7F66
)

// Cookie regex for extracting username
var cookieRegex = regexp.MustCompile(`mstshash=([^\r\n]+)`)

type rdpReader struct {
	conversation *core.ConversationInfo
}

// New returns a new RDP reader.
func (r *rdpReader) New(conversation *core.ConversationInfo) core.StreamDecoderInterface {
	return &rdpReader{
		conversation: conversation,
	}
}

// Decode parses RDP protocol from the stream.
func (r *rdpReader) Decode() {
	if Decoder.Writer == nil {
		rdpLog.Error("RDP Decoder.Writer is nil")
		return
	}

	var clientBuf, serverBuf bytes.Buffer

	for _, d := range r.conversation.Data {
		if d.Direction() == reassembly.TCPDirClientToServer {
			clientBuf.Write(d.Raw())
		} else {
			serverBuf.Write(d.Raw())
		}
	}

	clientData := clientBuf.Bytes()
	serverData := serverBuf.Bytes()

	// Parse connection request from client
	if len(clientData) >= 11 && clientData[0] == tpktVersion {
		msg := r.parseConnectionRequest(clientData)
		if msg != nil {
			r.enrichWithServerResponse(msg, serverData)
			msg.SrcIP = r.conversation.ClientIP
			msg.DstIP = r.conversation.ServerIP
			msg.SrcPort = int32(r.conversation.ClientPort)
			msg.DstPort = int32(r.conversation.ServerPort)
			msg.CommunityID = r.conversation.CommunityID

			err := Decoder.Writer.Write(msg)
			if err != nil {
				rdpLog.Error("failed to write RDP record", zap.Error(err))
			} else {
				atomic.AddInt64(&Decoder.NumRecordsWritten, 1)
			}
		}
	}
}

func (r *rdpReader) parseConnectionRequest(data []byte) *types.RDP {
	if len(data) < 11 {
		return nil
	}

	msg := &types.RDP{
		Timestamp:       r.conversation.FirstClientPacket.UnixNano(),
		ConnectionPhase: "Connection Request",
		IsRequest:       true,
	}

	// Parse TPKT header
	// data[0] = version (0x03)
	// data[1] = reserved (0x00)
	// data[2:4] = length
	tpktLength := binary.BigEndian.Uint16(data[2:4])
	if int(tpktLength) > len(data) {
		tpktLength = uint16(len(data))
	}

	// Parse X.224 header
	x224Length := data[4]
	x224Type := data[5]

	if x224Type != x224ConnectionRequest {
		return nil
	}

	// X.224 Connection Request format (MS-RDPBCGR 2.2.1.1):
	// TPKT (4 bytes) + X.224 header
	// X.224 header: Length(1) + Type(1) + DST-REF(2) + SRC-REF(2) + CLASS(1)
	// Variable part starts after X.224 fixed header (7 bytes from TPKT end = offset 11)
	offset := 11

	// Calculate end of X.224 CR TPDU (TPKT header + X.224 data)
	x224End := min(len(data), int(tpktLength))

	if int(x224Length) > 6 && len(data) > offset && offset < x224End {
		variableData := data[offset:x224End]

		// Parse Cookie if present (optional, starts with "Cookie:")
		if len(variableData) > 7 && bytes.HasPrefix(variableData, []byte("Cookie:")) {
			cookieEnd := bytes.Index(variableData, []byte("\r\n"))
			if cookieEnd > 0 && cookieEnd < len(variableData) {
				msg.Cookie = string(variableData[:cookieEnd])

				// Extract username from cookie
				if matches := cookieRegex.FindStringSubmatch(msg.Cookie); len(matches) > 1 {
					msg.Username = matches[1]
				}

				// Move past cookie + CRLF
				if cookieEnd+2 < len(variableData) {
					variableData = variableData[cookieEnd+2:]
				} else {
					variableData = nil
				}
			}
		}

		// Parse RDP Negotiation Request (optional, MS-RDPBCGR 2.2.1.1.1)
		if len(variableData) >= 8 && variableData[0] == RDPNegReq {
			r.parseNegotiationRequest(msg, variableData)
		}
	}

	return msg
}

func (r *rdpReader) parseNegotiationRequest(msg *types.RDP, data []byte) {
	if len(data) < 8 {
		return
	}

	// Type = data[0] (RDPNegReq = 0x01)
	// Flags = data[1]
	// Length = data[2:4] (always 8)
	requestedProtocols := binary.LittleEndian.Uint32(data[4:8])

	msg.RequestedProtocolsFlags = int32(requestedProtocols)

	var protocols []string
	if requestedProtocols == ProtocolRDP {
		protocols = append(protocols, "RDP")
	}
	if requestedProtocols&ProtocolSSL != 0 {
		protocols = append(protocols, "SSL")
		msg.UsesTLS = true
	}
	if requestedProtocols&ProtocolHybrid != 0 {
		protocols = append(protocols, "CredSSP/NLA")
		msg.UsesNLA = true
		msg.UsesCredSSP = true
	}
	if requestedProtocols&ProtocolRDSTLS != 0 {
		protocols = append(protocols, "RDSTLS")
	}
	if requestedProtocols&ProtocolHybridEx != 0 {
		protocols = append(protocols, "CredSSP/EarlyUserAuth")
		msg.UsesCredSSP = true
	}

	msg.RequestedProtocolNames = strings.Join(protocols, ",")
	msg.RequestedProtocols = msg.RequestedProtocolNames
}

func (r *rdpReader) enrichWithServerResponse(msg *types.RDP, serverData []byte) {
	if len(serverData) < 11 {
		return
	}

	// Check for TPKT header
	if serverData[0] != tpktVersion {
		return
	}

	// Check for X.224 Connection Confirm
	if serverData[5] != x224ConnectionConfirm {
		return
	}

	// Look for negotiation response
	x224Length := serverData[4]
	if x224Length > 6 && len(serverData) > 11 {
		offset := 11
		variableData := serverData[offset:]

		if len(variableData) >= 8 {
			negType := variableData[0]

			switch negType {
			case RDPNegRsp:
				r.parseNegotiationResponse(msg, variableData)
			case RDPNegFailure:
				r.parseNegotiationFailure(msg, variableData)
			}
		}
	}
}

func (r *rdpReader) parseNegotiationResponse(msg *types.RDP, data []byte) {
	if len(data) < 8 {
		return
	}

	// Type = data[0] (RDPNegRsp = 0x02)
	flags := data[1]
	// Length = data[2:4]
	selectedProtocol := binary.LittleEndian.Uint32(data[4:8])

	msg.SelectedProtocol = getSelectedProtocolName(selectedProtocol)
	msg.ConnectionSuccessful = true

	// Parse flags
	if flags&0x01 != 0 {
		msg.ExtendedClientDataSupported = true
	}
	if flags&0x02 != 0 {
		msg.DynamicDST = true // Server supports Graphics Dynamic Virtual Channel
	}
	if flags&0x08 != 0 {
		msg.RestrictedAdminMode = true
	}
	if flags&0x10 != 0 {
		msg.RemoteCredGuard = true
	}
}

func (r *rdpReader) parseNegotiationFailure(msg *types.RDP, data []byte) {
	if len(data) < 8 {
		return
	}

	// Type = data[0] (RDPNegFailure = 0x03)
	// Flags = data[1]
	// Length = data[2:4]
	failureCode := binary.LittleEndian.Uint32(data[4:8])

	msg.ConnectionSuccessful = false
	msg.ErrorCode = int32(failureCode)
	msg.ErrorDescription = getFailureCodeDescription(failureCode)
}

func getSelectedProtocolName(protocol uint32) string {
	switch protocol {
	case ProtocolRDP:
		return "RDP"
	case ProtocolSSL:
		return "SSL"
	case ProtocolHybrid:
		return "CredSSP/NLA"
	case ProtocolRDSTLS:
		return "RDSTLS"
	case ProtocolHybridEx:
		return "CredSSP/EarlyUserAuth"
	default:
		return "Unknown"
	}
}

func getFailureCodeDescription(code uint32) string {
	switch code {
	case 0x00000001:
		return "SSL_REQUIRED_BY_SERVER"
	case 0x00000002:
		return "SSL_NOT_ALLOWED_BY_SERVER"
	case 0x00000003:
		return "SSL_CERT_NOT_ON_SERVER"
	case 0x00000004:
		return "INCONSISTENT_FLAGS"
	case 0x00000005:
		return "HYBRID_REQUIRED_BY_SERVER"
	case 0x00000006:
		return "SSL_WITH_USER_AUTH_REQUIRED_BY_SERVER"
	default:
		return "Unknown failure"
	}
}
