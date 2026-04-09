/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package packet

import (
	"github.com/gogo/protobuf/proto"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

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
