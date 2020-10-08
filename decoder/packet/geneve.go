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

var geneveDecoder = newGoPacketDecoder(
	types.Type_NC_Geneve,
	layers.LayerTypeGeneve,
	"Geneve is a network virtualization overlay encapsulation protocol designed to establish tunnels between network virtualization end points (NVE) over an existing IP network",
	func(layer gopacket.Layer, timestamp int64) proto.Message {
		if geneve, ok := layer.(*layers.Geneve); ok {
			var opts []*types.GeneveOption
			if len(geneve.Options) > 0 {
				for _, o := range geneve.Options {
					opts = append(opts, &types.GeneveOption{
						Class:  int32(o.Class),
						Type:   int32(o.Type),
						Flags:  int32(o.Flags),
						Length: int32(o.Length),
						Data:   o.Data,
					})
				}
			}

			return &types.Geneve{
				Timestamp:      timestamp,
				Version:        int32(geneve.Version),
				OptionsLength:  int32(geneve.OptionsLength),
				OAMPacket:      geneve.OAMPacket,
				CriticalOption: geneve.CriticalOption,
				Protocol:       int32(geneve.Protocol),
				VNI:            geneve.VNI,
				Options:        opts,
			}
		}

		return nil
	},
)
