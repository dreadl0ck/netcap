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

var igmpEncoder = CreateLayerEncoder(
	types.Type_NC_IGMP,
	layers.LayerTypeIGMP,
	func(layer gopacket.Layer, timestamp string) proto.Message {
		if igmp, ok := layer.(*layers.IGMP); ok {
			var addresses []string
			for _, ip := range igmp.SourceAddresses {
				addresses = append(addresses, ip.String())
			}
			var records []*types.IGMPv3GroupRecord
			for _, r := range igmp.GroupRecords {
				var srca []string
				for _, ip := range r.SourceAddresses {
					srca = append(srca, ip.String())
				}
				records = append(records, &types.IGMPv3GroupRecord{
					Type:             int32(r.Type),
					AuxDataLen:       int32(r.AuxDataLen),
					NumberOfSources:  int32(r.NumberOfSources),
					MulticastAddress: r.MulticastAddress.String(),
					SourceAddresses:  srca,
				})
			}
			return &types.IGMP{
				Timestamp:               timestamp,
				Type:                    int32(igmp.Type),
				MaxResponseTime:         uint64(igmp.MaxResponseTime),
				Checksum:                int32(igmp.Checksum),
				GroupAddress:            []byte(igmp.GroupAddress),
				SupressRouterProcessing: igmp.SupressRouterProcessing,
				RobustnessValue:         int32(igmp.RobustnessValue),
				IntervalTime:            uint64(igmp.IntervalTime),
				SourceAddresses:         addresses,
				NumberOfGroupRecords:    int32(igmp.NumberOfGroupRecords),
				NumberOfSources:         int32(igmp.NumberOfSources),
				GroupRecords:            records,
				Version:                 int32(igmp.Version),
			}
		}
		return nil
	})
