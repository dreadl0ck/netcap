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

package iec62351

import (
	"bytes"
	"crypto/x509"
	"encoding/binary"
	"strconv"
	"sync/atomic"

	"go.uber.org/zap"

	"github.com/dreadl0ck/netcap/decoder/core"
	"github.com/dreadl0ck/netcap/types"
)

// IEC 62351 authentication mechanisms
const (
	AuthMechanismX509       = "X.509"
	AuthMechanismKerberos   = "Kerberos"
	AuthMechanismPassword   = "Password"
	AuthMechanismHMAC       = "HMAC"
	AuthMechanismDigitalSig = "DigitalSignature"
)

// IEC 62351-8 RBAC roles
const (
	RoleOperator    = "OPERATOR"
	RoleEngineer    = "ENGINEER"
	RoleViewer      = "VIEWER"
	RoleAdmin       = "SECADM"
	RoleAuditor     = "SECAUD"
	RoleMaintenance = "MAINT"
)

// IEC 62351-8 permissions
const (
	PermissionRead    = "READ"
	PermissionWrite   = "WRITE"
	PermissionControl = "CONTROL"
	PermissionCreate  = "CREATE"
	PermissionDelete  = "DELETE"
)

// Audit event types (IEC 62351-7)
const (
	AuditEventAuthentication = "AUTHENTICATION"
	AuditEventAuthorization  = "AUTHORIZATION"
	AuditEventKeyManagement  = "KEY_MANAGEMENT"
	AuditEventSecurityAlert  = "SECURITY_ALERT"
	AuditEventConfigChange   = "CONFIG_CHANGE"
	AuditEventSessionStart   = "SESSION_START"
	AuditEventSessionEnd     = "SESSION_END"
)

// Audit event outcomes
const (
	OutcomeSuccess = "SUCCESS"
	OutcomeFailure = "FAILURE"
	OutcomeUnknown = "UNKNOWN"
)

// Underlying protocol identifiers
const (
	ProtocolIEC61850    = "IEC61850"
	ProtocolIEC104      = "IEC60870-5-104"
	ProtocolDNP3SA      = "DNP3-SA"
	ProtocolTLSSecured  = "TLS-Secured"
)

type iec62351Reader struct {
	conversation *core.ConversationInfo
}

// New returns a new IEC 62351 reader.
func (r *iec62351Reader) New(conversation *core.ConversationInfo) core.StreamDecoderInterface {
	return &iec62351Reader{
		conversation: conversation,
	}
}

// Decode parses IEC 62351 security messages from the stream.
func (r *iec62351Reader) Decode() {
	if Decoder.Writer == nil {
		iec62351Log.Error("IEC62351 Decoder.Writer is nil")
		return
	}

	var buf bytes.Buffer

	for _, data := range r.conversation.Data {
		buf.Write(data.Raw())
	}

	frameData := buf.Bytes()
	offset := 0

	for offset < len(frameData)-8 {
		msg, consumed := r.parseSecurityMessage(frameData[offset:])
		if msg != nil {
			msg.SrcIP = r.conversation.ClientIP
			msg.DstIP = r.conversation.ServerIP
			msg.SrcPort = int32(r.conversation.ClientPort)
			msg.DstPort = int32(r.conversation.ServerPort)

			err := Decoder.Writer.Write(msg)
			if err != nil {
				iec62351Log.Error("failed to write IEC62351 record", zap.Error(err))
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

// parseSecurityMessage attempts to parse an IEC 62351 security message.
// Returns the parsed message and the number of bytes consumed.
func (r *iec62351Reader) parseSecurityMessage(data []byte) (*types.IEC62351, int) {
	if len(data) < 8 {
		return nil, 0
	}

	// Determine the underlying protocol and parse accordingly
	if isTLSHandshake(data) {
		return r.parseTLSSecurityMessage(data)
	}

	if isIEC104Frame(data) {
		return r.parseIEC104SecurityMessage(data)
	}

	if isIEC61850Frame(data) {
		return r.parseIEC61850SecurityMessage(data)
	}

	if isDNP3Frame(data) {
		return r.parseDNP3SAMessage(data)
	}

	return nil, 0
}

// isTLSHandshake checks if data starts with TLS record header
func isTLSHandshake(data []byte) bool {
	if len(data) < 6 {
		return false
	}
	// Content type 22 = Handshake, version 0x03XX
	return data[0] == 22 && data[1] == 0x03
}

// isIEC104Frame checks for IEC 60870-5-104 APCI header
func isIEC104Frame(data []byte) bool {
	return len(data) >= 6 && data[0] == 0x68
}

// isIEC61850Frame checks for IEC 61850 MMS over TPKT
func isIEC61850Frame(data []byte) bool {
	return len(data) >= 4 && data[0] == 0x03 // TPKT version 3
}

// isDNP3Frame checks for DNP3 frame start bytes
func isDNP3Frame(data []byte) bool {
	return len(data) >= 10 && data[0] == 0x05 && data[1] == 0x64
}

// parseTLSSecurityMessage parses TLS handshake messages for IEC 62351-3
func (r *iec62351Reader) parseTLSSecurityMessage(data []byte) (*types.IEC62351, int) {
	if len(data) < 6 {
		return nil, 0
	}

	msg := &types.IEC62351{
		Timestamp:          r.conversation.FirstClientPacket.UnixNano(),
		UnderlyingProtocol: ProtocolTLSSecured,
		IsSecurityRelevant: true,
	}

	// Parse TLS record layer
	contentType := data[0]
	if contentType != 22 { // Not a handshake
		return nil, 0
	}

	tlsVersion := binary.BigEndian.Uint16(data[1:3])
	msg.TLSVersion = getTLSVersionString(tlsVersion)

	recordLength := int(binary.BigEndian.Uint16(data[3:5]))
	if len(data) < 5+recordLength || recordLength < 1 {
		return nil, 0
	}

	consumed := 5 + recordLength

	// Parse handshake message
	handshakeType := data[5]
	msg.MessageType = int32(handshakeType)
	msg.MessageTypeName = getHandshakeTypeName(handshakeType)

	switch handshakeType {
	case 1: // ClientHello
		msg.IsRequest = true
		msg.IsAuthenticationEvent = true
		msg.AuditEventType = AuditEventAuthentication
		msg.AuditEventOutcome = OutcomeUnknown
		r.parseClientHello(msg, data[5:5+recordLength])

	case 2: // ServerHello
		msg.IsRequest = false
		msg.IsAuthenticationEvent = true
		msg.AuditEventType = AuditEventAuthentication
		r.parseServerHello(msg, data[5:5+recordLength])

	case 11: // Certificate
		msg.IsAuthenticationEvent = true
		msg.AuthenticationMechanism = AuthMechanismX509
		r.parseCertificateMessage(msg, data[5:5+recordLength])

	case 12: // ServerKeyExchange
		msg.IsKeyManagementEvent = true
		msg.AuditEventType = AuditEventKeyManagement

	case 15: // CertificateRequest
		msg.MutualAuthentication = true
		msg.IsAuthenticationEvent = true

	case 16: // ServerHelloDone
		msg.IsRequest = false

	case 20: // Finished
		msg.AuditEventType = AuditEventSessionStart
		msg.AuditEventOutcome = OutcomeSuccess
	}

	return msg, consumed
}

// parseIEC104SecurityMessage parses IEC 60870-5-104 security ASDUs
func (r *iec62351Reader) parseIEC104SecurityMessage(data []byte) (*types.IEC62351, int) {
	if len(data) < 12 {
		return nil, 0
	}

	// APCI header: start (1), length (1), control fields (4)
	apduLength := int(data[1]) + 2 // Length + start byte + length byte

	if len(data) < apduLength {
		return nil, 0
	}

	msg := &types.IEC62351{
		Timestamp:          r.conversation.FirstClientPacket.UnixNano(),
		UnderlyingProtocol: ProtocolIEC104,
		IsSecurityRelevant: true,
		SecurityVersion:    5, // IEC 62351-5
	}

	// ASDU starts at byte 6
	if len(data) < 10 {
		return msg, apduLength
	}

	asduType := data[6]
	msg.MessageType = int32(asduType)

	// Check if this is a security ASDU (type 80-95 per IEC 62351-5)
	if asduType >= 0x50 && asduType <= 0x5F {
		msg.MessageTypeName = getIEC104SecurityASDUName(asduType)
		r.parseIEC104SecurityASDU(msg, data[6:], asduType)
	} else {
		// Not a security ASDU, but may contain authentication extensions
		msg.MessageTypeName = "Standard ASDU with Security Extension"
	}

	// Parse qualifier and cause of transmission for context
	if len(data) >= 9 {
		cot := data[8] & 0x3F // Cause of transmission (lower 6 bits)
		if cot == 0 { // Unused/reserved - might indicate authentication
			msg.IsAuthenticationEvent = true
		}
	}

	return msg, apduLength
}

// parseIEC104SecurityASDU parses the security-specific ASDU content
func (r *iec62351Reader) parseIEC104SecurityASDU(msg *types.IEC62351, data []byte, asduType uint8) {
	switch asduType {
	case 0x50: // Authentication request
		msg.IsAuthenticationEvent = true
		msg.IsRequest = true
		msg.AuditEventType = AuditEventAuthentication
		if len(data) >= 8 {
			msg.ChallengeSequence = int32(binary.LittleEndian.Uint16(data[4:6]))
		}

	case 0x51: // Authentication response
		msg.IsAuthenticationEvent = true
		msg.IsRequest = false
		msg.AuditEventType = AuditEventAuthentication
		if len(data) >= 4 {
			// Check for success/failure in response
			statusByte := data[3]
			if statusByte == 0 {
				msg.AuditEventOutcome = OutcomeSuccess
				msg.MACValid = true
			} else {
				msg.AuditEventOutcome = OutcomeFailure
				msg.IsSecurityAlert = true
				msg.ErrorCode = int32(statusByte)
			}
		}

	case 0x52: // Key change request
		msg.IsKeyManagementEvent = true
		msg.IsRequest = true
		msg.IsCriticalOperation = true
		msg.AuditEventType = AuditEventKeyManagement

	case 0x53: // Key change response
		msg.IsKeyManagementEvent = true
		msg.IsRequest = false
		msg.AuditEventType = AuditEventKeyManagement

	case 0x54: // Error message
		msg.IsSecurityAlert = true
		msg.AuditEventOutcome = OutcomeFailure
		if len(data) >= 6 {
			msg.ErrorCode = int32(binary.LittleEndian.Uint16(data[4:6]))
			msg.ErrorMessage = getSecurityErrorMessage(msg.ErrorCode)
		}

	case 0x55: // User status change
		msg.IsAuthorizationEvent = true
		msg.AuditEventType = AuditEventAuthorization
		msg.IsCriticalOperation = true

	default:
		// Generic security ASDU
		msg.AuditEventType = AuditEventSecurityAlert
	}
}

// parseIEC61850SecurityMessage parses IEC 61850 MMS security extensions
func (r *iec62351Reader) parseIEC61850SecurityMessage(data []byte) (*types.IEC62351, int) {
	if len(data) < 7 {
		return nil, 0
	}

	// TPKT header: version (1), reserved (1), length (2)
	tpktLength := int(binary.BigEndian.Uint16(data[2:4]))
	if len(data) < tpktLength || tpktLength < 7 {
		return nil, 0
	}

	msg := &types.IEC62351{
		Timestamp:          r.conversation.FirstClientPacket.UnixNano(),
		UnderlyingProtocol: ProtocolIEC61850,
		IsSecurityRelevant: true,
		SecurityVersion:    6, // IEC 62351-6
	}

	// Skip TPKT (4 bytes) and COTP (variable, usually 3 bytes for data TPDU)
	// Look for MMS PDU with security extensions
	offset := 7
	if len(data) > offset {
		r.parseMMSSecurityExtensions(msg, data[offset:])
	}

	return msg, tpktLength
}

// parseMMSSecurityExtensions parses MMS security-related content
func (r *iec62351Reader) parseMMSSecurityExtensions(msg *types.IEC62351, data []byte) {
	if len(data) < 2 {
		return
	}

	// MMS uses ASN.1 BER encoding
	// Tag and length are at the start
	tag := data[0]
	
	// Determine message type based on MMS tag and context
	switch tag {
	case 0xA0: // Initiate-RequestPDU (with security)
		msg.IsRequest = true
		msg.IsAuthenticationEvent = true
		msg.AuditEventType = AuditEventSessionStart
		msg.MessageType = int32(MsgTypeAssociationRequest)
		msg.MessageTypeName = "AssociateRequest"

	case 0xA1: // Initiate-ResponsePDU
		msg.IsRequest = false
		msg.AuditEventType = AuditEventSessionStart
		msg.MessageType = int32(MsgTypeAssociationResponse)
		msg.MessageTypeName = "AssociateResponse"

	case 0xA2: // Initiate-ErrorPDU
		msg.IsSecurityAlert = true
		msg.AuditEventOutcome = OutcomeFailure
		msg.MessageType = int32(MsgTypeErrorMessage)
		msg.MessageTypeName = "AssociateError"

	case 0xA3: // Confirmed-RequestPDU
		msg.IsRequest = true
		// Check for security-related operations
		r.checkMMSSecurityOperation(msg, data[1:])

	case 0xA4: // Confirmed-ResponsePDU
		msg.IsRequest = false

	case 0xA5: // Confirmed-ErrorPDU
		msg.IsSecurityAlert = true
		msg.AuditEventOutcome = OutcomeFailure

	case 0xA8: // Conclude-RequestPDU
		msg.AuditEventType = AuditEventSessionEnd
		msg.MessageType = int32(MsgTypeReleaseRequest)
		msg.MessageTypeName = "ReleaseRequest"

	case 0xA9: // Conclude-ResponsePDU
		msg.AuditEventType = AuditEventSessionEnd
		msg.MessageType = int32(MsgTypeReleaseResponse)
		msg.MessageTypeName = "ReleaseResponse"
	}

	// Look for security OIDs in the PDU
	r.extractSecurityOIDs(msg, data)
}

// checkMMSSecurityOperation checks if an MMS operation is security-related
func (r *iec62351Reader) checkMMSSecurityOperation(msg *types.IEC62351, data []byte) {
	// Look for GetAccessControlList, SetAccessControlList operations
	// These are RBAC-related in IEC 62351-8
	for i := 0; i < len(data)-4; i++ {
		// Check for access control related OIDs or context tags
		if data[i] == 0x85 || data[i] == 0x86 { // Access control context tags
			msg.IsAuthorizationEvent = true
			msg.AuditEventType = AuditEventAuthorization
			break
		}
	}
}

// extractSecurityOIDs looks for IEC 62351 security OIDs in the data
func (r *iec62351Reader) extractSecurityOIDs(msg *types.IEC62351, data []byte) {
	// Look for OID tag (0x06) followed by IEC 62351 security OIDs
	for i := 0; i < len(data)-7; i++ {
		if data[i] == 0x06 { // OID tag
			oidLen := int(data[i+1])
			if oidLen > 0 && i+2+oidLen <= len(data) {
				oid := data[i+2 : i+2+oidLen]
				// Check for known security OIDs
				if isSecurityOID(oid) {
					msg.SecurityPolicy = formatOID(oid)
				}
			}
		}
	}
}

// parseDNP3SAMessage parses DNP3 Secure Authentication messages
func (r *iec62351Reader) parseDNP3SAMessage(data []byte) (*types.IEC62351, int) {
	if len(data) < 12 {
		return nil, 0
	}

	// DNP3 data link layer: start (2), length (1), control (1), dst (2), src (2), crc (2)
	frameLength := int(data[2]) + 5 // Length + header overhead

	if len(data) < frameLength {
		return nil, 0
	}

	msg := &types.IEC62351{
		Timestamp:          r.conversation.FirstClientPacket.UnixNano(),
		UnderlyingProtocol: ProtocolDNP3SA,
		IsSecurityRelevant: true,
		SecurityVersion:    5, // IEC 62351-5 / DNP3-SA
	}

	// Check direction from control byte
	control := data[3]
	msg.IsRequest = (control & 0x40) != 0 // PRM bit

	// Look for authentication objects (group 120)
	offset := 10 // After data link header
	for offset < len(data)-3 {
		if data[offset] == 0x78 { // Object group 120 = Authentication
			variation := data[offset+1]
			msg.MessageType = int32(variation)
			msg.MessageTypeName = getDNP3SAObjectName(variation)
			msg.IsAuthenticationEvent = true
			msg.AuditEventType = AuditEventAuthentication

			r.parseDNP3SAObject(msg, data[offset:], variation)
			break
		}
		offset++
	}

	return msg, frameLength
}

// parseDNP3SAObject parses DNP3 Secure Authentication objects
func (r *iec62351Reader) parseDNP3SAObject(msg *types.IEC62351, data []byte, variation uint8) {
	switch variation {
	case 1: // Authentication Challenge
		msg.IsRequest = true
		msg.MessageTypeName = "AuthenticationChallenge"
		if len(data) >= 10 {
			msg.ChallengeSequence = int32(binary.LittleEndian.Uint32(data[4:8]))
		}

	case 2: // Authentication Reply
		msg.IsRequest = false
		msg.MessageTypeName = "AuthenticationReply"

	case 3: // Aggressive Mode Request
		msg.IsRequest = true
		msg.MessageTypeName = "AggressiveModeRequest"

	case 4: // Session Key Status Request
		msg.IsKeyManagementEvent = true
		msg.AuditEventType = AuditEventKeyManagement
		msg.MessageTypeName = "SessionKeyStatusRequest"

	case 5: // Session Key Status
		msg.IsKeyManagementEvent = true
		msg.MessageTypeName = "SessionKeyStatus"

	case 6: // Session Key Change
		msg.IsKeyManagementEvent = true
		msg.IsCriticalOperation = true
		msg.MessageTypeName = "SessionKeyChange"

	case 7: // Error
		msg.IsSecurityAlert = true
		msg.AuditEventOutcome = OutcomeFailure
		msg.MessageTypeName = "AuthenticationError"
		if len(data) >= 6 {
			msg.ErrorCode = int32(binary.LittleEndian.Uint16(data[4:6]))
			msg.ErrorMessage = getDNP3SAErrorMessage(msg.ErrorCode)
		}

	case 8: // User Certificate
		msg.AuthenticationMechanism = AuthMechanismX509
		msg.MessageTypeName = "UserCertificate"

	case 9: // MAC Value
		msg.AuthenticationMechanism = AuthMechanismHMAC
		msg.MessageTypeName = "MACValue"

	case 10: // User Status Change
		msg.IsAuthorizationEvent = true
		msg.IsCriticalOperation = true
		msg.AuditEventType = AuditEventConfigChange
		msg.MessageTypeName = "UserStatusChange"
	}
}

// parseClientHello extracts security information from TLS ClientHello
func (r *iec62351Reader) parseClientHello(msg *types.IEC62351, data []byte) {
	if len(data) < 38 {
		return
	}

	// Handshake header: type (1), length (3)
	// ClientHello: version (2), random (32), session_id_length (1)...
	offset := 4 // Skip handshake header

	if offset+2 > len(data) {
		return
	}

	// Parse cipher suites to determine security policy
	// Skip: version (2), random (32), session_id (variable), cipher_suites_length (2)
	offset += 2 + 32 // version + random
	
	if offset >= len(data) {
		return
	}
	
	sessionIdLen := int(data[offset])
	offset += 1 + sessionIdLen

	if offset+2 >= len(data) {
		return
	}

	cipherSuitesLen := int(binary.BigEndian.Uint16(data[offset : offset+2]))
	offset += 2

	if cipherSuitesLen > 0 && offset+2 <= len(data) {
		// Extract first cipher suite as indicator
		firstCipherSuite := binary.BigEndian.Uint16(data[offset : offset+2])
		msg.SecurityPolicy = getCipherSuiteSecurityPolicy(firstCipherSuite)
	}
}

// parseServerHello extracts negotiated security parameters
func (r *iec62351Reader) parseServerHello(msg *types.IEC62351, data []byte) {
	if len(data) < 38 {
		return
	}

	offset := 4 // Skip handshake header

	if offset+2 > len(data) {
		return
	}

	// Version
	version := binary.BigEndian.Uint16(data[offset : offset+2])
	msg.TLSVersion = getTLSVersionString(version)
	offset += 2 + 32 // version + random

	if offset >= len(data) {
		return
	}

	sessionIdLen := int(data[offset])
	offset += 1

	if sessionIdLen > 0 && offset+sessionIdLen <= len(data) {
		// Session ID exists - session resumption
		msg.SessionId = formatSessionId(data[offset : offset+sessionIdLen])
	}
	offset += sessionIdLen

	if offset+2 > len(data) {
		return
	}

	// Cipher suite
	cipherSuite := binary.BigEndian.Uint16(data[offset : offset+2])
	msg.CipherSuite = getCipherSuiteName(cipherSuite)
	msg.AuditEventOutcome = OutcomeSuccess
}

// parseCertificateMessage extracts certificate information
func (r *iec62351Reader) parseCertificateMessage(msg *types.IEC62351, data []byte) {
	if len(data) < 10 {
		return
	}

	offset := 4 // Skip handshake header

	if offset+3 > len(data) {
		return
	}

	// Certificates length (3 bytes)
	certsLen := int(data[offset])<<16 | int(data[offset+1])<<8 | int(data[offset+2])
	offset += 3

	if certsLen == 0 || offset+3 > len(data) {
		return
	}

	// First certificate length (3 bytes)
	certLen := int(data[offset])<<16 | int(data[offset+1])<<8 | int(data[offset+2])
	offset += 3

	if certLen > 0 && offset+certLen <= len(data) {
		certData := data[offset : offset+certLen]
		cert, err := x509.ParseCertificate(certData)
		if err == nil {
			msg.CertificateSubject = cert.Subject.String()
			msg.CertificateIssuer = cert.Issuer.String()
			msg.CertificateSerial = cert.SerialNumber.String()
			msg.CertificateNotBefore = cert.NotBefore.UnixNano()
			msg.CertificateNotAfter = cert.NotAfter.UnixNano()

			// Check key usage
			if cert.KeyUsage != 0 {
				msg.KeyUsage = formatKeyUsage(cert.KeyUsage)
			}

			msg.CertificateValid = true // Parsed successfully
		}
	}
}

// Helper functions

func getTLSVersionString(version uint16) string {
	switch version {
	case 0x0300:
		return "SSL 3.0"
	case 0x0301:
		return "TLS 1.0"
	case 0x0302:
		return "TLS 1.1"
	case 0x0303:
		return "TLS 1.2"
	case 0x0304:
		return "TLS 1.3"
	default:
		return "Unknown"
	}
}

func getHandshakeTypeName(hsType uint8) string {
	switch hsType {
	case 0:
		return "HelloRequest"
	case 1:
		return "ClientHello"
	case 2:
		return "ServerHello"
	case 4:
		return "NewSessionTicket"
	case 8:
		return "EncryptedExtensions"
	case 11:
		return "Certificate"
	case 12:
		return "ServerKeyExchange"
	case 13:
		return "CertificateRequest"
	case 14:
		return "ServerHelloDone"
	case 15:
		return "CertificateVerify"
	case 16:
		return "ClientKeyExchange"
	case 20:
		return "Finished"
	default:
		return "Unknown"
	}
}

func getIEC104SecurityASDUName(asduType uint8) string {
	switch asduType {
	case 0x50:
		return "AuthenticationRequest"
	case 0x51:
		return "AuthenticationResponse"
	case 0x52:
		return "KeyChangeRequest"
	case 0x53:
		return "KeyChangeResponse"
	case 0x54:
		return "SecurityError"
	case 0x55:
		return "UserStatusChange"
	case 0x56:
		return "UpdateKeyRequest"
	case 0x57:
		return "UpdateKeyResponse"
	case 0x58:
		return "ChallengeMessage"
	case 0x59:
		return "ChallengeReply"
	default:
		return "SecurityASDU"
	}
}

func getDNP3SAObjectName(variation uint8) string {
	switch variation {
	case 1:
		return "AuthenticationChallenge"
	case 2:
		return "AuthenticationReply"
	case 3:
		return "AggressiveModeRequest"
	case 4:
		return "SessionKeyStatusRequest"
	case 5:
		return "SessionKeyStatus"
	case 6:
		return "SessionKeyChange"
	case 7:
		return "AuthenticationError"
	case 8:
		return "UserCertificate"
	case 9:
		return "MACValue"
	case 10:
		return "UserStatusChange"
	default:
		return "Unknown"
	}
}

func getSecurityErrorMessage(code int32) string {
	switch code {
	case 1:
		return "Authentication failure"
	case 2:
		return "Authorization failure"
	case 3:
		return "Key expired"
	case 4:
		return "Invalid certificate"
	case 5:
		return "Certificate revoked"
	case 6:
		return "Invalid signature"
	case 7:
		return "Replay attack detected"
	case 8:
		return "Session expired"
	default:
		return "Unknown error"
	}
}

func getDNP3SAErrorMessage(code int32) string {
	switch code {
	case 1:
		return "Authentication failed"
	case 2:
		return "Unexpected message"
	case 3:
		return "No response"
	case 4:
		return "Aggressive mode not supported"
	case 5:
		return "MAC algorithm not supported"
	case 6:
		return "Key wrap algorithm not supported"
	case 7:
		return "Authorization failed"
	default:
		return "Unknown error"
	}
}

func getCipherSuiteName(suite uint16) string {
	// Common IEC 62351 recommended cipher suites
	switch suite {
	case 0x002F:
		return "TLS_RSA_WITH_AES_128_CBC_SHA"
	case 0x0035:
		return "TLS_RSA_WITH_AES_256_CBC_SHA"
	case 0x003C:
		return "TLS_RSA_WITH_AES_128_CBC_SHA256"
	case 0x003D:
		return "TLS_RSA_WITH_AES_256_CBC_SHA256"
	case 0x009C:
		return "TLS_RSA_WITH_AES_128_GCM_SHA256"
	case 0x009D:
		return "TLS_RSA_WITH_AES_256_GCM_SHA384"
	case 0xC02B:
		return "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"
	case 0xC02C:
		return "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"
	case 0xC02F:
		return "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
	case 0xC030:
		return "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
	default:
		return "Unknown"
	}
}

func getCipherSuiteSecurityPolicy(suite uint16) string {
	// Classify cipher suite security level
	switch {
	case suite >= 0xC02B && suite <= 0xC030:
		return "IEC62351-Basic256Sha256"
	case suite >= 0x009C && suite <= 0x009D:
		return "IEC62351-Aes128-Sha256"
	case suite >= 0x002F && suite <= 0x003D:
		return "IEC62351-Basic128Rsa15"
	default:
		return "Unknown"
	}
}

func formatSessionId(sessionId []byte) string {
	if len(sessionId) == 0 {
		return ""
	}
	result := ""
	for i, b := range sessionId {
		if i > 0 && i%4 == 0 {
			result += "-"
		}
		result += string("0123456789ABCDEF"[b>>4]) + string("0123456789ABCDEF"[b&0x0F])
	}
	return result
}

func formatKeyUsage(usage x509.KeyUsage) string {
	var usages []string
	if usage&x509.KeyUsageDigitalSignature != 0 {
		usages = append(usages, "DigitalSignature")
	}
	if usage&x509.KeyUsageKeyEncipherment != 0 {
		usages = append(usages, "KeyEncipherment")
	}
	if usage&x509.KeyUsageDataEncipherment != 0 {
		usages = append(usages, "DataEncipherment")
	}
	if usage&x509.KeyUsageKeyAgreement != 0 {
		usages = append(usages, "KeyAgreement")
	}
	if usage&x509.KeyUsageCertSign != 0 {
		usages = append(usages, "CertSign")
	}
	if usage&x509.KeyUsageCRLSign != 0 {
		usages = append(usages, "CRLSign")
	}
	if len(usages) == 0 {
		return "None"
	}
	result := usages[0]
	for i := 1; i < len(usages); i++ {
		result += "," + usages[i]
	}
	return result
}

func isSecurityOID(oid []byte) bool {
	// Check for known IEC 62351 security OIDs
	// IEC 62351 OID prefix: 1.0.62351 = 0x28, 0xF5, 0x0F (approximate)
	if len(oid) < 3 {
		return false
	}
	// Simplified check - actual OIDs are more specific
	return oid[0] == 0x28 && oid[1] >= 0xCA
}

func formatOID(oid []byte) string {
	if len(oid) == 0 {
		return ""
	}
	result := ""
	for i, b := range oid {
		if i > 0 {
			result += "."
		}
		result += strconv.Itoa(int(b))
	}
	return result
}
