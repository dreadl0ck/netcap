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

var bfdDecoder = newGoPacketDecoder(
	types.Type_NC_BFD,
	layers.LayerTypeBFD,
	"Bidirectional Forwarding Detection (BFD) is a network protocol that is used to detect faults between two forwarding engines connected by a link",
	func(layer gopacket.Layer, timestamp int64) proto.Message {
		if bfd, ok := layer.(*layers.BFD); ok {
			return &types.BFD{
				Timestamp:                 timestamp,
				Version:                   int32(bfd.Version),
				Diagnostic:                int32(bfd.Diagnostic),
				State:                     int32(bfd.State),
				Poll:                      bfd.Poll,
				Final:                     bfd.Final,
				ControlPlaneIndependent:   bfd.ControlPlaneIndependent,
				AuthPresent:               bfd.AuthPresent,
				Demand:                    bfd.Demand,
				Multipoint:                bfd.Multipoint,
				DetectMultiplier:          int32(bfd.DetectMultiplier),
				MyDiscriminator:           int32(bfd.MyDiscriminator),
				YourDiscriminator:         int32(bfd.YourDiscriminator),
				DesiredMinTxInterval:      int32(bfd.DesiredMinTxInterval),
				RequiredMinRxInterval:     int32(bfd.RequiredMinRxInterval),
				RequiredMinEchoRxInterval: int32(bfd.RequiredMinEchoRxInterval),
				AuthHeader: &types.BFDAuthHeader{
					AuthType:       int32(bfd.AuthHeader.AuthType),
					KeyID:          int32(bfd.AuthHeader.KeyID),
					SequenceNumber: int32(bfd.AuthHeader.SequenceNumber),
					Data:           bfd.AuthHeader.Data,
				},
			}
		}

		return nil
	},
)
