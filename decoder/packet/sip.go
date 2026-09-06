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
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/gogo/protobuf/proto"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	"github.com/dreadl0ck/netcap/types"
)

// reCSeq parses CSeq header: "123 INVITE" -> number=123, method=INVITE
var reCSeq = regexp.MustCompile(`^(\d+)\s+(\w+)$`)

// sipMethodNames maps SIP method codes to names
var sipMethodNames = map[layers.SIPMethod]string{
	layers.SIPMethodInvite:    "INVITE",
	layers.SIPMethodAck:       "ACK",
	layers.SIPMethodBye:       "BYE",
	layers.SIPMethodCancel:    "CANCEL",
	layers.SIPMethodRegister:  "REGISTER",
	layers.SIPMethodOptions:   "OPTIONS",
	layers.SIPMethodPrack:     "PRACK",
	layers.SIPMethodSubscribe: "SUBSCRIBE",
	layers.SIPMethodNotify:    "NOTIFY",
	layers.SIPMethodPublish:   "PUBLISH",
	layers.SIPMethodInfo:      "INFO",
	layers.SIPMethodRefer:     "REFER",
	layers.SIPMethodMessage:   "MESSAGE",
	layers.SIPMethodUpdate:    "UPDATE",
}

// getFirstHeader returns the first value of a header (case-insensitive)
func getFirstSIPHeader(headers map[string][]string, key string) string {
	keyLower := strings.ToLower(key)
	for k, v := range headers {
		if strings.ToLower(k) == keyLower && len(v) > 0 {
			return v[0]
		}
	}
	return ""
}

var sipDecoder = newGoPacketDecoder(
	types.Type_NC_SIP,
	layers.LayerTypeSIP,
	"The Session Initiation Protocol is a signaling protocol used for initiating, maintaining, and terminating real-time sessions that include voice, video and messaging applications",
	func(layer gopacket.Layer, timestamp int64) proto.Message {
		if sip, ok := layer.(*layers.SIP); ok {
			var headers []string
			for k, v := range sip.Headers {
				headers = append(headers, k+":"+strings.Join(v, ","))
			}
			// sip.Headers is a map: sort so the record is reproducible
			sort.Strings(headers)

			// Get method name
			methodName := sipMethodNames[sip.Method]
			if methodName == "" {
				methodName = "Unknown"
			}

			// Extract security-relevant headers
			callID := getFirstSIPHeader(sip.Headers, "Call-ID")
			from := getFirstSIPHeader(sip.Headers, "From")
			to := getFirstSIPHeader(sip.Headers, "To")
			contact := getFirstSIPHeader(sip.Headers, "Contact")
			userAgent := getFirstSIPHeader(sip.Headers, "User-Agent")
			contentType := getFirstSIPHeader(sip.Headers, "Content-Type")
			contentLengthStr := getFirstSIPHeader(sip.Headers, "Content-Length")
			var contentLength int32
			if cl, err := strconv.Atoi(contentLengthStr); err == nil {
				contentLength = int32(cl)
			}

			// Extract additional security monitoring headers
			via := getFirstSIPHeader(sip.Headers, "Via")
			cseq := getFirstSIPHeader(sip.Headers, "CSeq")
			authorization := getFirstSIPHeader(sip.Headers, "Authorization")
			if authorization == "" {
				authorization = getFirstSIPHeader(sip.Headers, "Proxy-Authorization")
			}

			// Parse Max-Forwards header
			maxForwardsStr := getFirstSIPHeader(sip.Headers, "Max-Forwards")
			var maxForwards int32
			if mf, err := strconv.Atoi(maxForwardsStr); err == nil {
				maxForwards = int32(mf)
			}

			// Parse CSeq into number and method
			var cseqNumber int32
			var cseqMethod string
			if matches := reCSeq.FindStringSubmatch(strings.TrimSpace(cseq)); len(matches) == 3 {
				if num, err := strconv.Atoi(matches[1]); err == nil {
					cseqNumber = int32(num)
				}
				cseqMethod = matches[2]
			}

			var requestURI string
			if !sip.IsResponse {
				requestURI = sip.RequestURI
			}

			// Capture body if configured (for SDP analysis and VoIP security)
			var body []byte
			if conf.IncludePayloads {
				body = layer.LayerPayload()
			}

			sipMsg := &types.SIP{
				Timestamp:      timestamp,
				Version:        int32(sip.Version),
				Method:         int32(sip.Method),
				Headers:        headers,
				IsResponse:     sip.IsResponse,
				ResponseCode:   int32(sip.ResponseCode),
				ResponseStatus: sip.ResponseStatus,
				MethodName:     methodName,
				CallID:         callID,
				From:           from,
				To:             to,
				Contact:        contact,
				UserAgent:      userAgent,
				ContentType:    contentType,
				ContentLength:  contentLength,
				Body:           body,
				// New security monitoring fields
				Via:           via,
				CSeq:          cseq,
				CSeqNumber:    cseqNumber,
				CSeqMethod:    cseqMethod,
				RequestURI:    requestURI,
				MaxForwards:   maxForwards,
				Authorization: authorization,
			}

			// Perform security analysis
			analyzeSIPSecurity(sipMsg)

			return sipMsg
		}

		return nil
	},
)
