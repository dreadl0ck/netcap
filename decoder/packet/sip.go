/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) 2017-2020 Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

package packet

import (
	"strconv"
	"strings"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gogo/protobuf/proto"

	"github.com/dreadl0ck/netcap/types"
)

// sipMethodNames maps SIP method codes to names
var sipMethodNames = map[layers.SIPMethod]string{
	layers.SIPMethodInvite:   "INVITE",
	layers.SIPMethodAck:      "ACK",
	layers.SIPMethodBye:      "BYE",
	layers.SIPMethodCancel:   "CANCEL",
	layers.SIPMethodRegister: "REGISTER",
	layers.SIPMethodOptions:  "OPTIONS",
	layers.SIPMethodPrack:    "PRACK",
	layers.SIPMethodSubscribe: "SUBSCRIBE",
	layers.SIPMethodNotify:   "NOTIFY",
	layers.SIPMethodPublish:  "PUBLISH",
	layers.SIPMethodInfo:     "INFO",
	layers.SIPMethodRefer:    "REFER",
	layers.SIPMethodMessage:  "MESSAGE",
	layers.SIPMethodUpdate:   "UPDATE",
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

			// Capture body if configured (for SDP analysis and VoIP security)
			var body []byte
			if conf.IncludePayloads {
				body = layer.LayerPayload()
			}

			return &types.SIP{
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
			}
		}

		return nil
	},
)
