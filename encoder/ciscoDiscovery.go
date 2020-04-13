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

package encoder

import (
	"github.com/dreadl0ck/gopacket"
	"github.com/dreadl0ck/gopacket/layers"
	"github.com/dreadl0ck/netcap/types"
	"github.com/golang/protobuf/proto"
)

var ciscoDiscoveryEncoder = CreateLayerEncoder(types.Type_NC_CiscoDiscovery, layers.LayerTypeCiscoDiscovery, func(layer gopacket.Layer, timestamp string) proto.Message {
	if ciscoDiscovery, ok := layer.(*layers.CiscoDiscovery); ok {
		var values []*types.CiscoDiscoveryValue
		for _, v := range ciscoDiscovery.Values {
			values = append(values, &types.CiscoDiscoveryValue{
				Type:   int32(v.Type),
				Length: int32(v.Length),
				Value:  []byte(v.Value),
			})
		}
		return &types.CiscoDiscovery{
			Timestamp: timestamp,
			Version:   int32(ciscoDiscovery.Version),
			TTL:       int32(ciscoDiscovery.TTL),
			Checksum:  int32(ciscoDiscovery.Checksum),
			Values:    values,
		}
	}
	return nil
})
