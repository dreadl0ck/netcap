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
	"bytes"
	"encoding/base64"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/dreadl0ck/netcap/types"
)

const serviceSIP = "SIP"

var (
	// SIP request line pattern: METHOD sip:uri SIP/2.0
	reSIPRequestLine = regexp.MustCompile(`^(REGISTER|INVITE|ACK|BYE|CANCEL|OPTIONS|PRACK|SUBSCRIBE|NOTIFY|PUBLISH|INFO|REFER|MESSAGE|UPDATE)\s+sip:([^\s]+)\s+SIP/2\.0`)

	// SIP response line pattern: SIP/2.0 status-code reason
	reSIPResponseLine = regexp.MustCompile(`^SIP/2\.0\s+(\d{3})\s+(.*)`)

	// SIP Authorization header patterns
	reSIPAuthDigest = regexp.MustCompile(`(?i)(?:Authorization|Proxy-Authorization):\s*Digest\s+(.*)`)
	reSIPAuthBasic  = regexp.MustCompile(`(?i)(?:Authorization|Proxy-Authorization):\s*Basic\s+([A-Za-z0-9+/=]+)`)

	// SIP header patterns
	reSIPFrom   = regexp.MustCompile(`(?i)^From:\s*(.*)`)
	reSIPTo     = regexp.MustCompile(`(?i)^To:\s*(.*)`)
	reSIPCallID = regexp.MustCompile(`(?i)^Call-ID:\s*(.*)`)
	reSIPCSeq   = regexp.MustCompile(`(?i)^CSeq:\s*(\d+)\s+(\w+)`)
)

// sipHarvesterFunc extracts credentials from SIP authentication
// SIP uses HTTP-style Digest and Basic authentication for REGISTER requests
func sipHarvesterFunc(data []byte, ident string, ts time.Time) *types.Credentials {
	if len(data) < 20 {
		return nil
	}

	// Check for SIP message (request or response)
	// Handle both CRLF and LF line endings
	var lines [][]byte
	if bytes.Contains(data, []byte("\r\n")) {
		lines = bytes.Split(data, []byte("\r\n"))
	} else {
		lines = bytes.Split(data, []byte("\n"))
	}
	if len(lines) < 2 {
		return nil
	}

	firstLine := string(lines[0])

	// Try to extract credentials from Authorization header
	if creds := extractSIPDigestAuth(data, ident, ts, lines, firstLine); creds != nil {
		return creds
	}

	// Try Basic auth (less common but supported)
	if creds := extractSIPBasicAuth(data, ident, ts, lines, firstLine); creds != nil {
		return creds
	}

	// Check for authentication response (401/407)
	if creds := extractSIPAuthResponse(data, ident, ts, lines, firstLine); creds != nil {
		return creds
	}

	return nil
}

// extractSIPDigestAuth extracts SIP Digest authentication credentials
func extractSIPDigestAuth(data []byte, ident string, ts time.Time, lines [][]byte, firstLine string) *types.Credentials {
	// Find Authorization or Proxy-Authorization header
	matches := reSIPAuthDigest.FindSubmatch(data)
	if len(matches) < 2 {
		return nil
	}

	digestParams := string(matches[1])

	// Parse digest parameters
	params := parseSIPDigestParams(digestParams)

	username := params["username"]
	if username == "" {
		return nil
	}

	// Extract other SIP headers for context
	var method, callID, from, to string
	for _, line := range lines {
		lineStr := string(line)

		if m := reSIPFrom.FindStringSubmatch(lineStr); len(m) > 1 {
			from = strings.TrimSpace(m[1])
		} else if m := reSIPTo.FindStringSubmatch(lineStr); len(m) > 1 {
			to = strings.TrimSpace(m[1])
		} else if m := reSIPCallID.FindStringSubmatch(lineStr); len(m) > 1 {
			callID = strings.TrimSpace(m[1])
		} else if m := reSIPCSeq.FindStringSubmatch(lineStr); len(m) > 2 {
			method = m[2]
		}
	}

	// Extract method from request line if not found in CSeq
	if method == "" {
		if m := reSIPRequestLine.FindStringSubmatch(firstLine); len(m) > 1 {
			method = m[1]
		}
	}

	// Build Hashcat-compatible format for SIP Digest (mode 11400)
	// Format is same as HTTP Digest: username:realm:nonce:uri:nc:cnonce:qop:response
	// SIP Digest is essentially the same as HTTP Digest
	realm := params["realm"]
	nonce := params["nonce"]
	uri := params["uri"]
	response := params["response"]
	cnonce := params["cnonce"]
	nc := params["nc"]
	qop := params["qop"]

	var hashcatFormat string
	if realm != "" && nonce != "" && response != "" {
		hashcatFormat = fmt.Sprintf("%s:%s:%s:%s:%s:%s:%s:%s",
			username, realm, nonce, uri, nc, cnonce, qop, response)
	}

	notes := fmt.Sprintf("SIP %s Digest Auth", method)
	if from != "" {
		notes += ", From: " + from
	}

	return &types.Credentials{
		Timestamp: ts.UnixNano(),
		Service:   serviceSIP,
		Flow:      ident,
		User:      username,
		Password:  hashcatFormat, // Hashcat format if available
		Notes:     notes,
		HashType:  "SIP Digest MD5",
		Realm:     realm,
		Nonce:     nonce,
		Uri:       uri,
		Method:    method,
		Qop:       qop,
		Nc:        nc,
		Cnonce:    cnonce,
		SipMethod: method,
		SipCallId: callID,
		SipFrom:   from,
		SipTo:     to,
	}
}

// parseSIPDigestParams parses SIP Digest authentication parameters
func parseSIPDigestParams(digestLine string) map[string]string {
	params := make(map[string]string)

	// Split by comma and parse each part
	parts := strings.SplitSeq(digestLine, ",")
	for part := range parts {
		part = strings.TrimSpace(part)

		// Find equals sign
		before, after, ok := strings.Cut(part, "=")
		if !ok {
			continue
		}

		key := strings.ToLower(strings.TrimSpace(before))
		value := strings.TrimSpace(after)

		// Remove quotes
		value = strings.Trim(value, "\"")

		params[key] = value
	}

	return params
}

// extractSIPBasicAuth extracts SIP Basic authentication credentials
func extractSIPBasicAuth(data []byte, ident string, ts time.Time, lines [][]byte, firstLine string) *types.Credentials {
	matches := reSIPAuthBasic.FindSubmatch(data)
	if len(matches) < 2 {
		return nil
	}

	// Decode base64
	decoded, err := decodeBase64SIP(string(matches[1]))
	if err != nil {
		return nil
	}

	// Split into username:password
	parts := strings.SplitN(decoded, ":", 2)
	if len(parts) != 2 {
		return nil
	}

	username := parts[0]
	password := parts[1]

	// Extract method from request line
	var method string
	if m := reSIPRequestLine.FindStringSubmatch(firstLine); len(m) > 1 {
		method = m[1]
	}

	// Extract other SIP headers
	var callID, from, to string
	for _, line := range lines {
		lineStr := string(line)

		if m := reSIPFrom.FindStringSubmatch(lineStr); len(m) > 1 {
			from = strings.TrimSpace(m[1])
		} else if m := reSIPTo.FindStringSubmatch(lineStr); len(m) > 1 {
			to = strings.TrimSpace(m[1])
		} else if m := reSIPCallID.FindStringSubmatch(lineStr); len(m) > 1 {
			callID = strings.TrimSpace(m[1])
		}
	}

	return &types.Credentials{
		Timestamp: ts.UnixNano(),
		Service:   serviceSIP,
		Flow:      ident,
		User:      username,
		Password:  password,
		Notes:     fmt.Sprintf("SIP %s Basic Auth (plaintext)", method),
		SipMethod: method,
		SipCallId: callID,
		SipFrom:   from,
		SipTo:     to,
	}
}

// extractSIPAuthResponse extracts authentication challenge/result from SIP responses
// 401 Unauthorized - authentication challenge (not a failure on first occurrence)
// 407 Proxy Authentication Required - authentication challenge
// 200 OK (after auth) - successful authentication
// 403 Forbidden - authentication explicitly failed
func extractSIPAuthResponse(data []byte, ident string, ts time.Time, lines [][]byte, firstLine string) *types.Credentials {
	matches := reSIPResponseLine.FindStringSubmatch(firstLine)
	if len(matches) < 3 {
		return nil
	}

	statusCode := matches[1]
	// statusReason := matches[2]

	// Only process authentication-related responses
	if statusCode != "401" && statusCode != "407" && statusCode != "200" && statusCode != "403" {
		return nil
	}

	// Extract SIP headers for context
	var callID, from, to, cseqMethod string
	for _, line := range lines {
		lineStr := string(line)

		if m := reSIPFrom.FindStringSubmatch(lineStr); len(m) > 1 {
			from = strings.TrimSpace(m[1])
		} else if m := reSIPTo.FindStringSubmatch(lineStr); len(m) > 1 {
			to = strings.TrimSpace(m[1])
		} else if m := reSIPCallID.FindStringSubmatch(lineStr); len(m) > 1 {
			callID = strings.TrimSpace(m[1])
		} else if m := reSIPCSeq.FindStringSubmatch(lineStr); len(m) > 2 {
			cseqMethod = m[2]
		}
	}

	// Only track if this looks like an authentication flow (REGISTER method typically)
	if cseqMethod != "REGISTER" && cseqMethod != "INVITE" {
		return nil
	}

	var authSuccess bool
	var authSuccessSet bool
	var notes string

	switch statusCode {
	case "401":
		// 401 is a challenge, not necessarily a failure
		// First 401 is expected, only subsequent 401s after sending credentials indicate failure
		// We don't set authSuccessSet to true here because it's ambiguous
		authSuccessSet = false
		notes = "SIP 401 Unauthorized - authentication challenge"
	case "407":
		// 407 is also a challenge, same as 401
		authSuccessSet = false
		notes = "SIP 407 Proxy Authentication Required"
	case "403":
		// 403 Forbidden indicates definite auth failure
		authSuccess = false
		authSuccessSet = true
		notes = "SIP 403 Forbidden - authentication failed"
	case "200":
		// 200 OK indicates successful auth
		authSuccess = true
		authSuccessSet = true
		notes = fmt.Sprintf("SIP 200 OK for %s - authentication success", cseqMethod)
	}

	// Extract username from From header (SIP URI format: "name" <sip:user@domain>)
	username := extractSIPUsername(from)

	return &types.Credentials{
		Timestamp:      ts.UnixNano(),
		Service:        serviceSIP,
		Flow:           ident,
		User:           username,
		Notes:          notes,
		AuthSuccess:    authSuccess,
		AuthSuccessSet: authSuccessSet,
		SipMethod:      cseqMethod,
		SipCallId:      callID,
		SipFrom:        from,
		SipTo:          to,
	}
}

// extractSIPUsername extracts the username from a SIP From/To header value
// Format examples: "Display Name" <sip:user@domain>, sip:user@domain, user@domain
func extractSIPUsername(sipAddr string) string {
	// Look for sip: URI
	sipIdx := strings.Index(sipAddr, "sip:")
	if sipIdx != -1 {
		sipAddr = sipAddr[sipIdx+4:]
	}

	// Remove angle brackets
	sipAddr = strings.Trim(sipAddr, "<>")

	// Get just user@domain, removing parameters
	if semicolon := strings.Index(sipAddr, ";"); semicolon != -1 {
		sipAddr = sipAddr[:semicolon]
	}

	// Get just the user part
	if before, _, ok := strings.Cut(sipAddr, "@"); ok {
		return before
	}

	return sipAddr
}

// decodeBase64SIP decodes a base64 string for SIP credentials
func decodeBase64SIP(s string) (string, error) {
	decoded, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return "", err
	}
	return string(decoded), nil
}

// sipHarvester is the harvester definition for SIP
var sipHarvester = Harvester{
	Name:          "SIP",
	Description:   "Session Initiation Protocol - captures VoIP authentication credentials (Digest/Basic)",
	HarvesterFunc: sipHarvesterFunc,
}
