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
	"go.uber.org/zap"

	"github.com/dreadl0ck/netcap/decoder"
	decoderconfig "github.com/dreadl0ck/netcap/decoder/config"
	"github.com/dreadl0ck/netcap/decoder/core"
	logging "github.com/dreadl0ck/netcap/internal/logger"
	"github.com/dreadl0ck/netcap/types"
)

var iec62351Log = zap.NewNop()

const serviceIEC62351 = "IEC62351"

// IEC 62351 security message type identifiers
// These are used within the security extensions for power system protocols
const (
	// IEC 62351-5: Secure Authentication for IEC 61850 and IEC 60870-5
	MsgTypeAuthenticationRequest  = 0x01
	MsgTypeAuthenticationResponse = 0x02
	MsgTypeChallengeRequest       = 0x03
	MsgTypeChallengeResponse      = 0x04
	MsgTypeKeyUpdateRequest       = 0x05
	MsgTypeKeyUpdateResponse      = 0x06
	MsgTypeKeyConfirmation        = 0x07
	MsgTypeErrorMessage           = 0x08

	// IEC 62351-6: Security for IEC 61850 profiles
	MsgTypeAssociationRequest    = 0x10
	MsgTypeAssociationResponse   = 0x11
	MsgTypeAbortRequest          = 0x12
	MsgTypeReleaseRequest        = 0x13
	MsgTypeReleaseResponse       = 0x14

	// IEC 62351-7: Audit/Logging messages
	MsgTypeAuditEvent            = 0x20
	MsgTypeSecurityAlert         = 0x21
	MsgTypeAccessControlEvent    = 0x22

	// IEC 62351-8: Role-Based Access Control
	MsgTypeAccessRequest         = 0x30
	MsgTypeAccessResponse        = 0x31
	MsgTypeRoleDefinition        = 0x32
	MsgTypePermissionChange      = 0x33

	// IEC 62351-9: Key Management
	MsgTypeSymmetricKeyRequest   = 0x40
	MsgTypeSymmetricKeyResponse  = 0x41
	MsgTypeKeyDistribution       = 0x42
	MsgTypeKeyRevocation         = 0x43
)

// Signature patterns for detecting IEC 62351 security messages
// These patterns help identify security-related traffic in IEC 61850 and IEC 60870-5-104
var (
	// IEC 61850 MMS signature with security extensions
	// MMS uses ASN.1 BER encoding, security extensions have specific OID patterns
	iec61850MMSSecurityOID = []byte{0x06, 0x05, 0x28, 0xCA, 0x22} // Partial OID for IEC 61850 security

	// TLS/SSL for IEC 62351-3 transport security
	tlsHandshakeClientHello = byte(0x01)
	tlsHandshakeServerHello = byte(0x02)
	tlsHandshakeCertificate = byte(0x0B)

	// Common security authentication headers
	securityAuthHeader = []byte{0x62, 0x35, 0x31} // "621" in ASCII as a marker
)

// Decoder for IEC 62351 protocol analysis and writing audit records to disk.
var Decoder = &decoder.StreamDecoder{
	Type:        types.Type_NC_IEC62351,
	Name:        serviceIEC62351,
	Description: "IEC 62351 is a security standard for power system communications (IEC 61850, IEC 60870-5, DNP3)",
	PostInit: func(d *decoder.StreamDecoder) error {
		var err error
		iec62351Log, _, err = logging.InitZapLogger(
			decoderconfig.Instance.Out,
			"iec62351",
			decoderconfig.Instance.Debug,
		)
		return err
	},
	CanDecode: func(client, server []byte) bool {
		// IEC 62351 security extensions can appear in various underlying protocols
		// We check for security-related patterns in:
		// 1. IEC 61850 MMS security extensions (TCP port 102)
		// 2. IEC 60870-5-104 security ASDUs (TCP port 2404)
		// 3. TLS-secured power system communications
		// 4. DNP3 Secure Authentication (DNP3-SA)

		return canDecodeIEC62351(client) || canDecodeIEC62351(server)
	},
	DeInit: func(sd *decoder.StreamDecoder) error {
		return iec62351Log.Sync()
	},
	Factory: &iec62351Reader{},
	Typ:     core.TCP, // IEC 62351 uses TCP for secure communications
}

// canDecodeIEC62351 checks if the data contains IEC 62351 security protocol messages.
func canDecodeIEC62351(data []byte) bool {
	if len(data) < 8 {
		return false
	}

	// Check for IEC 61850 MMS with security extensions
	if hasIEC61850SecurityExtensions(data) {
		return true
	}

	// Check for IEC 60870-5-104 security ASDUs
	if hasIEC104SecurityASDU(data) {
		return true
	}

	// Check for TLS-secured power system communications
	if hasTLSSecurityHandshake(data) {
		return true
	}

	// Check for DNP3 Secure Authentication headers
	if hasDNP3SecureAuth(data) {
		return true
	}

	// Check for explicit IEC 62351 security authentication header
	if hasSecurityAuthenticationHeader(data) {
		return true
	}

	return false
}

// hasIEC61850SecurityExtensions checks for IEC 61850 MMS security OIDs
func hasIEC61850SecurityExtensions(data []byte) bool {
	// MMS (Manufacturing Message Specification) uses TPKT header (RFC 1006)
	// TPKT: version (1 byte), reserved (1 byte), length (2 bytes)
	if len(data) < 10 {
		return false
	}

	// Check for TPKT header (version 3)
	if data[0] != 0x03 {
		return false
	}

	// Look for security-related OID patterns in the MMS PDU
	for i := 0; i < len(data)-len(iec61850MMSSecurityOID); i++ {
		match := true
		for j := 0; j < len(iec61850MMSSecurityOID); j++ {
			if data[i+j] != iec61850MMSSecurityOID[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}

	return false
}

// hasIEC104SecurityASDU checks for IEC 60870-5-104 security ASDU types
func hasIEC104SecurityASDU(data []byte) bool {
	// IEC 60870-5-104 uses APCI header (6 bytes) followed by ASDU
	if len(data) < 12 {
		return false
	}

	// Check for APCI start bytes (0x68 = start, then length)
	if data[0] != 0x68 {
		return false
	}

	// ASDU starts at byte 6, type identifier at first byte of ASDU
	// Security type identifiers are in range 0x50-0x5F (per IEC 62351-5)
	asduType := data[6]
	if asduType >= 0x50 && asduType <= 0x5F {
		return true
	}

	// Also check for authentication challenge/response patterns
	// These may appear in the information object area
	if len(data) >= 20 {
		// Look for challenge/response structures
		for i := 6; i < len(data)-4; i++ {
			if data[i] == MsgTypeChallengeRequest || data[i] == MsgTypeChallengeResponse ||
				data[i] == MsgTypeAuthenticationRequest || data[i] == MsgTypeAuthenticationResponse {
				return true
			}
		}
	}

	return false
}

// hasTLSSecurityHandshake checks for TLS handshake messages (IEC 62351-3)
func hasTLSSecurityHandshake(data []byte) bool {
	if len(data) < 6 {
		return false
	}

	// TLS record layer: content type (1), version (2), length (2)
	// Content type 22 = Handshake
	if data[0] != 22 {
		return false
	}

	// Check TLS version (1.0: 0x0301, 1.1: 0x0302, 1.2: 0x0303, 1.3: 0x0304)
	if data[1] != 0x03 || (data[2] < 0x01 || data[2] > 0x04) {
		return false
	}

	// Check handshake message type at offset 5
	if len(data) > 5 {
		handshakeType := data[5]
		switch handshakeType {
		case tlsHandshakeClientHello, tlsHandshakeServerHello, tlsHandshakeCertificate:
			return true
		}
	}

	return false
}

// hasDNP3SecureAuth checks for DNP3 Secure Authentication (DNP3-SA) headers
func hasDNP3SecureAuth(data []byte) bool {
	// DNP3 start bytes: 0x05 0x64
	if len(data) < 12 {
		return false
	}

	if data[0] != 0x05 || data[1] != 0x64 {
		return false
	}

	// DNP3-SA uses object group 120 for authentication
	// Look for authentication object group in the application layer
	// After data link layer (10 bytes min) and transport layer (1 byte)
	for i := 11; i < len(data)-2; i++ {
		// Object group 120 (0x78) = Authentication
		if data[i] == 0x78 {
			return true
		}
	}

	return false
}

// hasSecurityAuthenticationHeader checks for explicit IEC 62351 security headers
func hasSecurityAuthenticationHeader(data []byte) bool {
	if len(data) < len(securityAuthHeader)+2 {
		return false
	}

	for i := 0; i < len(data)-len(securityAuthHeader); i++ {
		match := true
		for j := 0; j < len(securityAuthHeader); j++ {
			if data[i+j] != securityAuthHeader[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}

	return false
}

