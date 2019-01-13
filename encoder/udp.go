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

var udpEncoder = CreateLayerEncoder(types.Type_NC_UDP, layers.LayerTypeUDP, func(layer gopacket.Layer, timestamp string) proto.Message {
	if udp, ok := layer.(*layers.UDP); ok {
		var payload []byte
		if CapturePayload {
			payload = layer.LayerPayload()
		}
		return &types.UDP{
			Timestamp:      timestamp,
			SrcPort:        int32(udp.SrcPort),
			DstPort:        int32(udp.DstPort),
			Length:         int32(udp.Length),
			Checksum:       int32(udp.Checksum),
			PayloadEntropy: Entropy(udp.Payload),
			PayloadSize:    int32(len(udp.Payload)),
			Payload:        payload,
		}
	}
	return nil
})
