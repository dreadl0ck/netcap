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
	"github.com/dreadl0ck/netcap/types"
	"github.com/golang/protobuf/proto"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

var ipSecESPEncoder = CreateLayerEncoder(types.Type_NC_IPSecESP, layers.LayerTypeIPSecESP, func(layer gopacket.Layer, timestamp string) proto.Message {
	if ipsecesp, ok := layer.(*layers.IPSecESP); ok {
		return &types.IPSecESP{
			Timestamp:    timestamp,
			SPI:          int32(ipsecesp.SPI),            // int32
			Seq:          int32(ipsecesp.Seq),            // int32
			LenEncrypted: int32(len(ipsecesp.Encrypted)), // int32
		}
	}
	return nil
})
