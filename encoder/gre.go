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

var greEncoder = CreateLayerEncoder(types.Type_NC_GRE, layers.LayerTypeGRE, func(layer gopacket.Layer, timestamp string) proto.Message {
	if gre, ok := layer.(*layers.GRE); ok {
		return &types.GRE{
			Timestamp:         timestamp,
			ChecksumPresent:   bool(gre.ChecksumPresent),
			RoutingPresent:    bool(gre.RoutingPresent),
			KeyPresent:        bool(gre.KeyPresent),
			SeqPresent:        bool(gre.SeqPresent),
			StrictSourceRoute: bool(gre.StrictSourceRoute),
			AckPresent:        bool(gre.AckPresent),
			RecursionControl:  int32(gre.RecursionControl),
			Flags:             int32(gre.Flags),
			Version:           int32(gre.Version),
			Protocol:          int32(gre.Protocol),
			Checksum:          int32(gre.Checksum),
			Offset:            int32(gre.Offset),
			Key:               uint32(gre.Key),
			Seq:               uint32(gre.Seq),
			Ack:               uint32(gre.Ack),
			// @TODO: DEBUG nil pointer exception when acessing gre.Next
			// Routing: encodeGRERouting(gre.AddressFamily, gre.SREOffset, gre.SRELength, gre.RoutingInformation, nil),
		}
	}
	return nil
})

func encodeGRERouting(AddressFamily uint16, SREOffset, SRELength uint8, RoutingInformation []byte, next *layers.GRERouting) *types.GRERouting {

	var r *types.GRERouting
	if next != nil {
		r = encodeGRERouting(next.AddressFamily, next.SREOffset, next.SRELength, next.RoutingInformation, next.Next)
	}

	return &types.GRERouting{
		AddressFamily:      int32(AddressFamily),
		SREOffset:          int32(SREOffset),
		SRELength:          int32(SRELength),
		RoutingInformation: RoutingInformation,
		Next:               r,
	}
}
