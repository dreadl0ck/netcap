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
	"github.com/gogo/protobuf/proto"
)

var tcpEncoder = CreateLayerEncoder(
	types.Type_NC_TCP,
	layers.LayerTypeTCP,
	"The Transmission Control Protocol (TCP) is a connection-oriented communications protocol, that facilitates the exchange of messages between computing devices in a network",
	func(layer gopacket.Layer, timestamp string) proto.Message {
		if tcp, ok := layer.(*layers.TCP); ok {
			var (
				opts    []*types.TCPOption
				payload []byte
			)
			if c.IncludePayloads {
				payload = layer.LayerPayload()
			}
			var e float64
			if c.CalculateEntropy {
				e = Entropy(tcp.Payload)
			}
			for _, o := range tcp.Options {
				opts = append(opts, &types.TCPOption{
					OptionData:   o.OptionData,
					OptionLength: int32(o.OptionLength),
					OptionType:   int32(o.OptionType),
				})
			}
			return &types.TCP{
				Timestamp:      timestamp,
				SrcPort:        int32(tcp.SrcPort),
				DstPort:        int32(tcp.DstPort),
				SeqNum:         uint32(tcp.Seq),
				AckNum:         uint32(tcp.Ack),
				DataOffset:     int32(tcp.DataOffset),
				FIN:            bool(tcp.FIN),
				SYN:            bool(tcp.SYN),
				RST:            bool(tcp.RST),
				PSH:            bool(tcp.PSH),
				ACK:            bool(tcp.ACK),
				URG:            bool(tcp.URG),
				ECE:            bool(tcp.ECE),
				CWR:            bool(tcp.CWR),
				NS:             bool(tcp.NS),
				Window:         int32(tcp.Window),
				Checksum:       int32(tcp.Checksum),
				Urgent:         int32(tcp.Urgent),
				Padding:        tcp.Padding,
				Options:        opts,
				PayloadEntropy: e,
				PayloadSize:    int32(len(tcp.Payload)),
				Payload:        payload,
			}
		}
		return nil
	},
)
