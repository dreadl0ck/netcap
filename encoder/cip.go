/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) 2017 Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

package encoder

import (
	"github.com/dreadl0ck/gopacket"
	"github.com/dreadl0ck/gopacket/layers"
	"github.com/dreadl0ck/netcap/types"
	"github.com/golang/protobuf/proto"
)

var cipEncoder = CreateLayerEncoder(types.Type_NC_CIP, layers.LayerTypeCIP, func(layer gopacket.Layer, timestamp string) proto.Message {
	if cip, ok := layer.(*layers.CIP); ok {
		var payload []byte
		if CapturePayload {
			payload = cip.Data
		}
		var additional []uint32
		if cip.Response {
			for _, v := range cip.AdditionalStatus {
				additional = append(additional, uint32(v))
			}
		}
		return &types.CIP{
			Timestamp:        timestamp,
			Response:         bool(cip.Response),
			ServiceID:        int32(cip.ServiceID),
			ClassID:          uint32(cip.ClassID),
			InstanceID:       uint32(cip.InstanceID),
			Status:           int32(cip.Status),
			AdditionalStatus: additional,
			Data:             payload,
		}
	}
	return nil
})
