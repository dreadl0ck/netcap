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
	"github.com/gogo/protobuf/proto"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	"github.com/dreadl0ck/netcap/types"
)

var cipDecoder = newGoPacketDecoder(
	types.Type_NC_CIP,
	layers.LayerTypeCIP,
	"The Common Industrial Protocol (CIP) is an industrial protocol for industrial automation applications",
	func(layer gopacket.Layer, timestamp int64) proto.Message {
		if cip, ok := layer.(*layers.CIP); ok {
			var payload []byte
			if conf.IncludePayloads {
				payload = layer.LayerPayload()
			}
			additional := make([]uint32, 0, len(cip.AdditionalStatus))
			if cip.Response {
				for _, v := range cip.AdditionalStatus {
					additional = append(additional, uint32(v))
				}
			}

			// Handle optional pointer fields
			var classID, instanceID uint32
			if cip.ClassID != nil {
				classID = *cip.ClassID
			}
			if cip.InstanceID != nil {
				instanceID = *cip.InstanceID
			}

			return &types.CIP{
				Timestamp:        timestamp,
				Response:         cip.Response,
				ServiceID:        int32(cip.Service),
				ClassID:          classID,
				InstanceID:       instanceID,
				Status:           int32(cip.Status),
				AdditionalStatus: additional,
				Data:             payload,
			}
		}

		return nil
	},
)
