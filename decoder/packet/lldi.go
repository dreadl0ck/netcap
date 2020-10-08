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

var linkLayerDiscoveryInfoDecoder = newGoPacketDecoder(
	types.Type_NC_LinkLayerDiscoveryInfo,
	layers.LayerTypeLinkLayerDiscoveryInfo,
	"The Link Layer Discovery Protocol is a vendor-neutral link layer protocol used by network devices for advertising their identity, capabilities, and neighbors on a local area network based on IEEE 802 technology, principally wired Ethernet",
	func(layer gopacket.Layer, timestamp int64) proto.Message {
		if lldi, ok := layer.(*layers.LinkLayerDiscoveryInfo); ok {
			var (
				tlvs          []*types.LLDPOrgSpecificTLV
				undecodedTlvs []*types.LinkLayerDiscoveryValue
			)
			if lldi.OrgTLVs != nil {
				for _, o := range lldi.OrgTLVs {
					tlvs = append(tlvs, &types.LLDPOrgSpecificTLV{
						OUI:     uint32(o.OUI),
						SubType: int32(o.SubType),
						Info:    o.Info,
					})
				}
			}
			if lldi.Unknown != nil {
				for _, o := range lldi.Unknown {
					undecodedTlvs = append(undecodedTlvs, &types.LinkLayerDiscoveryValue{
						Length: int32(o.Length),
						Type:   int32(o.Type),
						Value:  o.Value,
					})
				}
			}

			return &types.LinkLayerDiscoveryInfo{
				Timestamp:       timestamp,
				PortDescription: lldi.PortDescription,
				SysName:         lldi.SysName,
				SysDescription:  lldi.SysDescription,
				SysCapabilities: &types.LLDPSysCapabilities{
					SystemCap: &types.LLDPCapabilities{
						Other:       lldi.SysCapabilities.SystemCap.Other,
						Repeater:    lldi.SysCapabilities.SystemCap.Repeater,
						Bridge:      lldi.SysCapabilities.SystemCap.Bridge,
						WLANAP:      lldi.SysCapabilities.SystemCap.WLANAP,
						Router:      lldi.SysCapabilities.SystemCap.Router,
						Phone:       lldi.SysCapabilities.SystemCap.Phone,
						DocSis:      lldi.SysCapabilities.SystemCap.DocSis,
						StationOnly: lldi.SysCapabilities.SystemCap.StationOnly,
						CVLAN:       lldi.SysCapabilities.SystemCap.CVLAN,
						SVLAN:       lldi.SysCapabilities.SystemCap.SVLAN,
						TMPR:        lldi.SysCapabilities.SystemCap.TMPR,
					},
					EnabledCap: &types.LLDPCapabilities{
						Other:       lldi.SysCapabilities.EnabledCap.Other,
						Repeater:    lldi.SysCapabilities.EnabledCap.Repeater,
						Bridge:      lldi.SysCapabilities.EnabledCap.Bridge,
						WLANAP:      lldi.SysCapabilities.EnabledCap.WLANAP,
						Router:      lldi.SysCapabilities.EnabledCap.Router,
						Phone:       lldi.SysCapabilities.EnabledCap.Phone,
						DocSis:      lldi.SysCapabilities.EnabledCap.DocSis,
						StationOnly: lldi.SysCapabilities.EnabledCap.StationOnly,
						CVLAN:       lldi.SysCapabilities.EnabledCap.CVLAN,
						SVLAN:       lldi.SysCapabilities.EnabledCap.SVLAN,
						TMPR:        lldi.SysCapabilities.EnabledCap.TMPR,
					},
				},
				MgmtAddress: &types.LLDPMgmtAddress{
					Subtype:          int32(lldi.MgmtAddress.Subtype),
					Address:          lldi.MgmtAddress.Address,
					InterfaceSubtype: int32(lldi.MgmtAddress.InterfaceSubtype),
					InterfaceNumber:  lldi.MgmtAddress.InterfaceNumber,
					// OID:              lldi.MgmtAddress.OID,
				},
				OrgTLVs: tlvs,
				Unknown: undecodedTlvs,
			}
		}

		return nil
	},
)
