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

// getMLDv2RecordTypeName returns a human-readable name for the record type
func getMLDv2RecordTypeName(recordType layers.MLDv2MulticastAddressRecordType) string {
	switch recordType {
	case layers.MLDv2MulticastAddressRecordTypeModeIsIncluded:
		return "MODE_IS_INCLUDE"
	case layers.MLDv2MulticastAddressRecordTypeModeIsExcluded:
		return "MODE_IS_EXCLUDE"
	case layers.MLDv2MulticastAddressRecordTypeChangeToIncludeMode:
		return "CHANGE_TO_INCLUDE_MODE"
	case layers.MLDv2MulticastAddressRecordTypeChangeToExcludeMode:
		return "CHANGE_TO_EXCLUDE_MODE"
	case layers.MLDv2MulticastAddressRecordTypeAllowNewSources:
		return "ALLOW_NEW_SOURCES"
	case layers.MLDv2MulticastAddressRecordTypeBlockOldSources:
		return "BLOCK_OLD_SOURCES"
	default:
		return "Unknown"
	}
}

var mldv2ReportDecoder = newGoPacketDecoder(
	types.Type_NC_MLDv2MulticastListenerReport,
	layers.LayerTypeMLDv2MulticastListenerReport,
	"MLDv2 Multicast Listener Report is sent by IP nodes to report current multicast listening state or changes (RFC 3810)",
	func(layer gopacket.Layer, timestamp int64) proto.Message {
		if mld, ok := layer.(*layers.MLDv2MulticastListenerReportMessage); ok {
			records := make([]*types.MLDv2MulticastAddressRecord, 0, len(mld.MulticastAddressRecords))
			hasJoinRecords := false
			hasLeaveRecords := false

			for _, r := range mld.MulticastAddressRecords {
				sourceAddrs := make([]string, 0, len(r.SourceAddresses))
				for _, ip := range r.SourceAddresses {
					sourceAddrs = append(sourceAddrs, ip.String())
				}

				// Track join/leave record types per RFC 3810
				switch r.RecordType {
				case layers.MLDv2MulticastAddressRecordTypeModeIsIncluded,
					layers.MLDv2MulticastAddressRecordTypeModeIsExcluded,
					layers.MLDv2MulticastAddressRecordTypeChangeToIncludeMode,
					layers.MLDv2MulticastAddressRecordTypeChangeToExcludeMode:
					hasJoinRecords = true
				case layers.MLDv2MulticastAddressRecordTypeAllowNewSources,
					layers.MLDv2MulticastAddressRecordTypeBlockOldSources:
					hasLeaveRecords = true
				}

				records = append(records, &types.MLDv2MulticastAddressRecord{
					RecordType:       int32(r.RecordType),
					RecordTypeName:   getMLDv2RecordTypeName(r.RecordType),
					AuxDataLen:       int32(r.AuxDataLen),
					NumberOfSources:  int32(r.N),
					MulticastAddress: r.MulticastAddress.String(),
					SourceAddresses:  sourceAddrs,
					AuxiliaryData:    r.AuxiliaryData,
				})
			}

			return &types.MLDv2MulticastListenerReport{
				Timestamp:                       timestamp,
				NumberOfMulticastAddressRecords: int32(mld.NumberOfMulticastAddressRecords),
				MulticastAddressRecords:         records,
				HasJoinRecords:                  hasJoinRecords,
				HasLeaveRecords:                 hasLeaveRecords,
			}
		}

		return nil
	},
)

