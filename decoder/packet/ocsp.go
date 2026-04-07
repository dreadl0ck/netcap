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

package packet

import (
	"bytes"
	"encoding/hex"
	"strings"

	"golang.org/x/crypto/ocsp" //nolint:staticcheck

	"github.com/gogo/protobuf/proto"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	"github.com/dreadl0ck/netcap/types"
)

// OCSP response status names
var ocspResponseStatusNames = map[int]string{
	0: "successful",
	1: "malformedRequest",
	2: "internalError",
	3: "tryLater",
	5: "sigRequired",
	6: "unauthorized",
}

var ocspDecoder = newPacketDecoder(
	types.Type_NC_OCSP,
	"OCSP",
	"Online Certificate Status Protocol checks certificate revocation status",
	nil,
	func(p gopacket.Packet) proto.Message {
		// OCSP is carried over HTTP, look for it in TCP payload
		tcpLayer := p.Layer(layers.LayerTypeTCP)
		if tcpLayer == nil {
			return nil
		}

		tcp, ok := tcpLayer.(*layers.TCP)
		if !ok {
			return nil
		}

		payload := tcp.Payload
		if len(payload) < 20 {
			return nil
		}

		// Look for OCSP response in HTTP body
		// OCSP responses start with a SEQUENCE tag (0x30) after HTTP headers
		var isResponse bool
		var body []byte

		payloadStr := string(payload)

		if strings.Contains(payloadStr, "application/ocsp-response") {
			isResponse = true
			// Find the body after \r\n\r\n
			if idx := bytes.Index(payload, []byte("\r\n\r\n")); idx >= 0 {
				body = payload[idx+4:]
			}
		} else if strings.Contains(payloadStr, "application/ocsp-request") {
			isResponse = false
			if idx := bytes.Index(payload, []byte("\r\n\r\n")); idx >= 0 {
				body = payload[idx+4:]
			}
		} else {
			return nil
		}

		if len(body) == 0 {
			return nil
		}

		var srcIP, dstIP string
		if nl := p.NetworkLayer(); nl != nil {
			srcIP = nl.NetworkFlow().Src().String()
			dstIP = nl.NetworkFlow().Dst().String()
		}

		if isResponse {
			resp, err := ocsp.ParseResponse(body, nil)
			if err != nil {
				// Try to parse just the status from the outer wrapper
				// OCSPResponse ::= SEQUENCE { responseStatus ENUMERATED, ... }
				if len(body) > 4 && body[0] == 0x30 {
					return &types.OCSP{
						Timestamp:  p.Metadata().Timestamp.UnixNano(),
						IsResponse: true,
						SrcIP:      srcIP,
						DstIP:      dstIP,
					}
				}
				return nil
			}

			var certStatus string
			switch resp.Status {
			case ocsp.Good:
				certStatus = "good"
			case ocsp.Revoked:
				certStatus = "revoked"
			case ocsp.Unknown:
				certStatus = "unknown"
			}

			var responderID string
			if len(resp.RawResponderName) > 0 {
				responderID = hex.EncodeToString(resp.RawResponderName)
			} else if len(resp.ResponderKeyHash) > 0 {
				responderID = hex.EncodeToString(resp.ResponderKeyHash)
			}

			return &types.OCSP{
				Timestamp:      p.Metadata().Timestamp.UnixNano(),
				IsResponse:     true,
				ResponseStatus: 0, // successful (we parsed it)
				CertSerial:     resp.SerialNumber.String(),
				CertStatus:     certStatus,
				ResponderID:    responderID,
				ProducedAt:     resp.ProducedAt.UnixNano(),
				ThisUpdate:     resp.ThisUpdate.UnixNano(),
				NextUpdate:     resp.NextUpdate.UnixNano(),
				SrcIP:          srcIP,
				DstIP:          dstIP,
			}
		}

		// OCSP request - basic record
		return &types.OCSP{
			Timestamp:  p.Metadata().Timestamp.UnixNano(),
			IsResponse: false,
			SrcIP:      srcIP,
			DstIP:      dstIP,
		}
	},
	nil,
)
