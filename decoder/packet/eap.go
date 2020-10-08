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
	"github.com/dreadl0ck/gopacket"
	"github.com/dreadl0ck/gopacket/layers"
	"github.com/gogo/protobuf/proto"

	"github.com/dreadl0ck/netcap/types"
)

var eapDecoder = newGoPacketDecoder(
	types.Type_NC_EAP,
	layers.LayerTypeEAP,
	"Extensible Authentication Protocol is an authentication framework frequently used in network and internet connections",
	func(layer gopacket.Layer, timestamp int64) proto.Message {
		if eap, ok := layer.(*layers.EAP); ok {
			return &types.EAP{
				Timestamp: timestamp,
				Code:      int32(eap.Code),
				Id:        int32(eap.Id),
				Length:    int32(eap.Length),
				Type:      int32(eap.Type),
				TypeData:  eap.TypeData,
			}
		}

		return nil
	},
)
