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
	"fmt"
	"time"
	"unicode"

	"github.com/dreadl0ck/netcap/types"
)

const serviceSOCKS = "SOCKS"

// SOCKS5 authentication method negotiation
// Client sends: VER(1) + NMETHODS(1) + METHODS(NMETHODS)
// Server sends: VER(1) + METHOD(1)
//
// SOCKS5 username/password authentication (RFC 1929)
// Client sends: VER(1) + ULEN(1) + UNAME(ULEN) + PLEN(1) + PASSWD(PLEN)
// Server sends: VER(1) + STATUS(1)

const (
	socks4Version = 0x04
	socks5Version = 0x05

	// SOCKS5 authentication methods
	socksAuthNone         = 0x00
	socksAuthGSSAPI       = 0x01
	socksAuthUserPass     = 0x02
	socksAuthNoAcceptable = 0xFF

	// SOCKS5 user/pass auth version
	socksUserPassVersion = 0x01

	// SOCKS5 reply codes
	socksReplySuccess     = 0x00
	socksReplyGeneralFail = 0x01
	socksReplyNotAllowed  = 0x02
	socksReplyNetUnreach  = 0x03
	socksReplyHostUnreach = 0x04
	socksReplyConnRefused = 0x05
	socksReplyTTLExpired  = 0x06
	socksReplyCmdNotSupp  = 0x07
	socksReplyAddrNotSupp = 0x08

	// SOCKS4 reply codes
	socks4ReplyGranted    = 0x5A
	socks4ReplyFailed     = 0x5B
	socks4ReplyNoIdentd   = 0x5C
	socks4ReplyIdentdFail = 0x5D
)

// socksHarvesterFunc extracts credentials from SOCKS proxy authentication
// Supports SOCKS4 (username only) and SOCKS5 (username/password)
// Note: Port filtering is now handled centrally by the harvester engine (HarvesterPortFilter setting)
func socksHarvesterFunc(data []byte, ident string, ts time.Time) *types.Credentials {
	if len(data) < 3 {
		return nil
	}

	// Check for SOCKS5 username/password authentication
	if creds := parseSOCKS5UserPass(data, ident, ts); creds != nil {
		return creds
	}

	// Check for SOCKS4 request with username
	if creds := parseSOCKS4Request(data, ident, ts); creds != nil {
		return creds
	}

	// Check for SOCKS5 auth response
	if creds := parseSOCKS5AuthResponse(data, ident, ts); creds != nil {
		return creds
	}

	return nil
}

// isValidCredentialString checks if a string looks like a valid credential (username or password)
// Returns false for strings that contain non-printable characters or look like garbage
func isValidCredentialString(s string) bool {
	if len(s) == 0 {
		return false
	}

	// Check for non-printable or non-ASCII characters
	for _, c := range s {
		// Must be printable ASCII (32-126)
		if c < 32 || c > 126 {
			return false
		}
	}

	// Count alphanumeric characters
	alphanumCount := 0
	for _, c := range s {
		if unicode.IsLetter(c) || unicode.IsDigit(c) {
			alphanumCount++
		}
	}

	// At least 50% should be alphanumeric for a reasonable credential
	if len(s) > 2 && float64(alphanumCount)/float64(len(s)) < 0.5 {
		return false
	}

	return true
}

// parseSOCKS5UserPass extracts username/password from SOCKS5 auth request
// Format: VER(1) + ULEN(1) + UNAME(ULEN) + PLEN(1) + PASSWD(PLEN)
func parseSOCKS5UserPass(data []byte, ident string, ts time.Time) *types.Credentials {
	// Check for SOCKS5 user/pass auth version (0x01)
	if len(data) < 2 || data[0] != socksUserPassVersion {
		return nil
	}

	ulen := int(data[1])
	// Sanity check: username length should be reasonable (1-255 chars)
	if ulen == 0 || ulen > 255 || len(data) < 2+ulen+1 {
		return nil
	}

	username := string(data[2 : 2+ulen])

	// Validate username contains printable characters
	if !isValidCredentialString(username) {
		return nil
	}

	plenOffset := 2 + ulen
	if plenOffset >= len(data) {
		return nil
	}

	plen := int(data[plenOffset])
	// Sanity check: password length should be reasonable (1-255 chars)
	if plen == 0 || plen > 255 || plenOffset+1+plen > len(data) {
		return nil
	}

	password := string(data[plenOffset+1 : plenOffset+1+plen])

	// Validate password contains printable characters
	if !isValidCredentialString(password) {
		return nil
	}

	return &types.Credentials{
		Timestamp:    ts.UnixNano(),
		Service:      serviceSOCKS,
		Flow:         ident,
		User:         username,
		Password:     password,
		Notes:        "SOCKS5 Username/Password Authentication",
		SocksVersion: socks5Version,
	}
}

// parseSOCKS4Request extracts username from SOCKS4 CONNECT/BIND request
// Format: VER(1) + CMD(1) + DSTPORT(2) + DSTIP(4) + USERID(variable) + NULL(1)
// SOCKS4a adds: DOMAIN(variable) + NULL(1) after USERID if DSTIP is 0.0.0.x
func parseSOCKS4Request(data []byte, ident string, ts time.Time) *types.Credentials {
	if len(data) < 9 || data[0] != socks4Version {
		return nil
	}

	cmd := data[1]
	// Check for valid SOCKS4 commands (1=CONNECT, 2=BIND)
	if cmd != 0x01 && cmd != 0x02 {
		return nil
	}

	// Find the NULL terminator for USERID (starts at offset 8)
	useridEnd := -1
	for i := 8; i < len(data) && i < 264; i++ { // Limit search to reasonable length
		if data[i] == 0x00 {
			useridEnd = i
			break
		}
	}

	if useridEnd == -1 || useridEnd == 8 {
		// No username or empty username
		return nil
	}

	// Sanity check: username length should be reasonable
	if useridEnd-8 > 255 {
		return nil
	}

	username := string(data[8:useridEnd])

	// Validate username contains printable characters
	if !isValidCredentialString(username) {
		return nil
	}

	return &types.Credentials{
		Timestamp:    ts.UnixNano(),
		Service:      serviceSOCKS,
		Flow:         ident,
		User:         username,
		Password:     "", // SOCKS4 doesn't have password auth
		Notes:        "SOCKS4 USERID",
		SocksVersion: socks4Version,
	}
}

// parseSOCKS5AuthResponse parses SOCKS5 authentication response
// Format: VER(1) + STATUS(1)
func parseSOCKS5AuthResponse(data []byte, ident string, ts time.Time) *types.Credentials {
	if len(data) != 2 || data[0] != socksUserPassVersion {
		return nil
	}

	status := data[1]
	var authSuccess bool
	var statusStr string

	if status == socksReplySuccess {
		authSuccess = true
		statusStr = "success"
	} else {
		authSuccess = false
		statusStr = fmt.Sprintf("failed (code %d)", status)
	}

	return &types.Credentials{
		Timestamp:      ts.UnixNano(),
		Service:        serviceSOCKS,
		Flow:           ident,
		Notes:          fmt.Sprintf("SOCKS5 Auth Response: %s", statusStr),
		SocksVersion:   socks5Version,
		SocksStatus:    statusStr,
		AuthSuccess:    authSuccess,
		AuthSuccessSet: true,
	}
}

// socksHarvester is the harvester definition for SOCKS
var socksHarvester = Harvester{
	Name:          "SOCKS",
	Description:   "SOCKS Proxy Protocol - captures proxy authentication credentials (SOCKS4/SOCKS5)",
	HarvesterFunc: socksHarvesterFunc,
}
