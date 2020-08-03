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

package decoder

import (
	"github.com/dreadl0ck/gopacket"
	"github.com/dreadl0ck/gopacket/layers"
	"github.com/dreadl0ck/netcap/types"
	"github.com/gogo/protobuf/proto"
)

var ethernetIPDecoder = NewGoPacketDecoder(
	types.Type_NC_ENIP,
	layers.LayerTypeENIP,
	"Industrial network protocol that adapts the Common Industrial Protocol to standard Ethernet",
	func(layer gopacket.Layer, timestamp string) proto.Message {
		if enip, ok := layer.(*layers.ENIP); ok {
			cmdSpecificData := &types.ENIPCommandSpecificData{
				Cmd:  uint32(enip.CommandSpecific.Cmd),
				Data: enip.CommandSpecific.Data,
			}
			return &types.ENIP{
				Timestamp:       timestamp,
				Command:         uint32(enip.Command),
				Length:          uint32(enip.Length),
				SessionHandle:   uint32(enip.SessionHandle),
				Status:          uint32(enip.Status),
				SenderContext:   []byte(enip.SenderContext),
				Options:         uint32(enip.Options),
				CommandSpecific: cmdSpecificData,
			}
		}
		return nil
	},
)
