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
	"net"
	"time"

	"github.com/dreadl0ck/netcap/types"
)

const serviceRADIUS = "RADIUS"

// RADIUS packet codes
const (
	radiusAccessRequest   = 1
	radiusAccessAccept    = 2
	radiusAccessReject    = 3
	radiusAccessChallenge = 11
)

// RADIUS attribute types
const (
	radiusAttrUserName         = 1
	radiusAttrUserPassword     = 2
	radiusAttrCHAPPassword     = 3
	radiusAttrNASIPAddress     = 4
	radiusAttrFramedIPAddress  = 8
	radiusAttrReplyMessage     = 18
	radiusAttrCallingStationId = 31
	radiusAttrCalledStationId  = 30
	radiusAttrConnectInfo      = 77
	radiusAttrTunnelClientEnd  = 66
)

// radiusHarvesterFunc extracts credentials from RADIUS packets
// RADIUS is used for network access authentication (802.1X, VPN, WiFi, etc.)
// Format: Code(1) + Identifier(1) + Length(2) + Authenticator(16) + Attributes(variable)
func radiusHarvesterFunc(data []byte, ident string, ts time.Time) *types.Credentials {
	if len(data) < 20 {
		return nil
	}

	code := data[0]
	// identifier := data[1]
	length := binary.BigEndian.Uint16(data[2:4])
	// authenticator := data[4:20]

	// Validate length
	if int(length) > len(data) || length < 20 {
		return nil
	}

	// Only process Access-Request, Access-Accept, and Access-Reject
	if code != radiusAccessRequest && code != radiusAccessAccept && code != radiusAccessReject && code != radiusAccessChallenge {
		return nil
	}

	// Parse attributes
	attrs := parseRADIUSAttributes(data[20:length])

	var username, password, mac, framedAddr, connectInfo, replyMsg string
	var authSuccess bool
	var authSuccessSet bool

	// Extract relevant attributes
	if val, ok := attrs[radiusAttrUserName]; ok {
		username = string(val)
	}
	if val, ok := attrs[radiusAttrUserPassword]; ok {
		// User-Password is XOR'd with MD5(shared_secret + authenticator)
		// We can't decrypt it without the shared secret, but we note it's present
		password = fmt.Sprintf("<encrypted:%d bytes>", len(val))
	}
	if val, ok := attrs[radiusAttrCHAPPassword]; ok {
		// CHAP password is also encrypted
		password = fmt.Sprintf("<CHAP:%d bytes>", len(val))
	}
	if val, ok := attrs[radiusAttrCallingStationId]; ok {
		mac = string(val)
	}
	if val, ok := attrs[radiusAttrFramedIPAddress]; ok && len(val) == 4 {
		framedAddr = net.IP(val).String()
	}
	if val, ok := attrs[radiusAttrConnectInfo]; ok {
		connectInfo = string(val)
	}
	if val, ok := attrs[radiusAttrReplyMessage]; ok {
		replyMsg = string(val)
	}

	// Determine authentication result
	switch code {
	case radiusAccessAccept:
		authSuccess = true
		authSuccessSet = true
	case radiusAccessReject:
		authSuccess = false
		authSuccessSet = true
	case radiusAccessChallenge:
		// Challenge doesn't indicate final auth result
		authSuccessSet = false
	}

	// Only create credential record if we have a username or it's a response
	if username == "" && code == radiusAccessRequest {
		return nil
	}

	// Determine code name for notes
	codeName := "Unknown"
	switch code {
	case radiusAccessRequest:
		codeName = "Access-Request"
	case radiusAccessAccept:
		codeName = "Access-Accept"
	case radiusAccessReject:
		codeName = "Access-Reject"
	case radiusAccessChallenge:
		codeName = "Access-Challenge"
	}

	notes := fmt.Sprintf("RADIUS %s", codeName)
	if connectInfo != "" {
		notes += ", Connect: " + connectInfo
	}
	if replyMsg != "" {
		notes += ", Reply: " + replyMsg
	}

	return &types.Credentials{
		Timestamp:      ts.UnixNano(),
		Service:        serviceRADIUS,
		Flow:           ident,
		User:           username,
		Password:       password,
		Notes:          notes,
		AuthSuccess:    authSuccess,
		AuthSuccessSet: authSuccessSet,
		MacAddress:     mac,
		FramedAddress:  framedAddr,
		ConnectInfo:    connectInfo,
		ReplyMessage:   replyMsg,
	}
}

// parseRADIUSAttributes parses RADIUS attributes from the attribute section
// Attribute format: Type(1) + Length(1) + Value(Length-2)
func parseRADIUSAttributes(data []byte) map[byte][]byte {
	attrs := make(map[byte][]byte)
	offset := 0

	for offset+2 <= len(data) {
		attrType := data[offset]
		attrLen := int(data[offset+1])

		// Validate attribute length
		if attrLen < 2 || offset+attrLen > len(data) {
			break
		}

		// Extract attribute value
		if attrLen > 2 {
			attrs[attrType] = data[offset+2 : offset+attrLen]
		}

		offset += attrLen
	}

	return attrs
}

// radiusHarvester is the harvester definition for RADIUS
var radiusHarvester = Harvester{
	Name:          "RADIUS",
	Description:   "Remote Authentication Dial-In User Service - captures authentication requests and results",
	HarvesterFunc: radiusHarvesterFunc,
}

