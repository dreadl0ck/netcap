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
	"github.com/dreadl0ck/gopacket"
	"github.com/dreadl0ck/gopacket/layers"
)

var bfdEncoder = CreateLayerEncoder(types.Type_NC_BFD, layers.LayerTypeBFD, func(layer gopacket.Layer, timestamp string) proto.Message {
	if bfd, ok := layer.(*layers.BFD); ok {
		return &types.BFD{
			Timestamp:                 timestamp,
			Version:                   int32(bfd.Version),
			Diagnostic:                int32(bfd.Diagnostic),
			State:                     int32(bfd.State),
			Poll:                      bool(bfd.Poll),
			Final:                     bool(bfd.Final),
			ControlPlaneIndependent:   bool(bfd.ControlPlaneIndependent),
			AuthPresent:               bool(bfd.AuthPresent),
			Demand:                    bool(bfd.Demand),
			Multipoint:                bool(bfd.Multipoint),
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
})
