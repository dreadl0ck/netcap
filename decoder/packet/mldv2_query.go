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
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gogo/protobuf/proto"

	"github.com/dreadl0ck/netcap/types"
)

var mldv2QueryDecoder = newGoPacketDecoder(
	types.Type_NC_MLDv2MulticastListenerQuery,
	layers.LayerTypeMLDv2MulticastListenerQuery,
	"MLDv2 Multicast Listener Query is sent by multicast routers to query the multicast listening state of neighboring interfaces (RFC 3810)",
	func(layer gopacket.Layer, timestamp int64) proto.Message {
		if mld, ok := layer.(*layers.MLDv2MulticastListenerQueryMessage); ok {
			sourceAddrs := make([]string, 0, len(mld.SourceAddresses))
			for _, ip := range mld.SourceAddresses {
				sourceAddrs = append(sourceAddrs, ip.String())
			}

			// Determine query type based on RFC 3810
			multicastAddrStr := mld.MulticastAddress.String()
			isGeneralQuery := multicastAddrStr == "::" || mld.MulticastAddress.IsUnspecified()
			hasSourceAddresses := len(mld.SourceAddresses) > 0
			isGroupSpecificQuery := !isGeneralQuery && !hasSourceAddresses
			isGroupAndSourceQuery := !isGeneralQuery && hasSourceAddresses

			return &types.MLDv2MulticastListenerQuery{
				Timestamp:                     timestamp,
				MaximumResponseCode:           int32(mld.MaximumResponseCode),
				MulticastAddress:              multicastAddrStr,
				SuppressRoutersideProcessing:  mld.SuppressRoutersideProcessing,
				QueriersRobustnessVariable:    int32(mld.QueriersRobustnessVariable),
				QueriersQueryIntervalCode:     int32(mld.QueriersQueryIntervalCode),
				NumberOfSources:               int32(mld.NumberOfSources),
				SourceAddresses:               sourceAddrs,
				IsGeneralQuery:                isGeneralQuery,
				IsGroupSpecificQuery:          isGroupSpecificQuery,
				IsGroupAndSourceQuery:         isGroupAndSourceQuery,
			}
		}

		return nil
	},
)

