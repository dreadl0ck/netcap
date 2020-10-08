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

var ciscoDiscoveryInfoDecoder = newGoPacketDecoder(
	types.Type_NC_CiscoDiscoveryInfo,
	layers.LayerTypeCiscoDiscoveryInfo,
	"Cisco Discovery Protocol is a proprietary Data Link Layer protocol used to share information about other directly connected Cisco equipment, such as the operating system version and IP address",
	func(layer gopacket.Layer, timestamp int64) proto.Message {
		if ciscoDiscoveryInfo, ok := layer.(*layers.CiscoDiscoveryInfo); ok {
			var (
				addresses     []string
				mgmtAddresses []string
				cdvs          []*types.CiscoDiscoveryValue
				ipNets        []*types.IPNet
			)
			for _, v := range ciscoDiscoveryInfo.Addresses {
				addresses = append(addresses, v.String())
			}
			for _, v := range ciscoDiscoveryInfo.Unknown {
				cdvs = append(cdvs, &types.CiscoDiscoveryValue{
					Type:   int32(v.Type),
					Length: int32(v.Length),
					Value:  v.Value,
				})
			}
			for _, v := range ciscoDiscoveryInfo.MgmtAddresses {
				mgmtAddresses = append(mgmtAddresses, v.String())
			}
			for _, v := range ciscoDiscoveryInfo.IPPrefixes {
				ipNets = append(ipNets, &types.IPNet{
					IP:     v.IP.String(),
					IPMask: v.Mask.String(),
				})
			}

			return &types.CiscoDiscoveryInfo{
				Timestamp: timestamp,
				CDPHello: &types.CDPHello{
					ProtocolID:       int32(ciscoDiscoveryInfo.CDPHello.ProtocolID),
					ClusterMaster:    string(ciscoDiscoveryInfo.CDPHello.ClusterMaster),
					Unknown1:         string(ciscoDiscoveryInfo.CDPHello.Unknown1),
					Version:          int32(ciscoDiscoveryInfo.CDPHello.Version),
					SubVersion:       int32(ciscoDiscoveryInfo.CDPHello.SubVersion),
					Status:           int32(ciscoDiscoveryInfo.CDPHello.Status),
					Unknown2:         int32(ciscoDiscoveryInfo.CDPHello.Unknown2),
					ClusterCommander: string(ciscoDiscoveryInfo.CDPHello.ClusterCommander),
					SwitchMAC:        string(ciscoDiscoveryInfo.CDPHello.SwitchMAC),
					Unknown3:         int32(ciscoDiscoveryInfo.CDPHello.Unknown3),
					ManagementVLAN:   int32(ciscoDiscoveryInfo.CDPHello.ManagementVLAN),
				},
				DeviceID:  ciscoDiscoveryInfo.DeviceID,
				Addresses: addresses,
				PortID:    ciscoDiscoveryInfo.PortID,
				Capabilities: &types.CDPCapabilities{
					L3Router:        ciscoDiscoveryInfo.Capabilities.L3Router,
					TBBridge:        ciscoDiscoveryInfo.Capabilities.TBBridge,
					SPBridge:        ciscoDiscoveryInfo.Capabilities.SPBridge,
					L2Switch:        ciscoDiscoveryInfo.Capabilities.L2Switch,
					IsHost:          ciscoDiscoveryInfo.Capabilities.IsHost,
					IGMPFilter:      ciscoDiscoveryInfo.Capabilities.IGMPFilter,
					L1Repeater:      ciscoDiscoveryInfo.Capabilities.L1Repeater,
					IsPhone:         ciscoDiscoveryInfo.Capabilities.IsPhone,
					RemotelyManaged: ciscoDiscoveryInfo.Capabilities.RemotelyManaged,
				},
				Version:    ciscoDiscoveryInfo.Version,
				Platform:   ciscoDiscoveryInfo.Platform,
				IPPrefixes: ipNets,
				VTPDomain:  ciscoDiscoveryInfo.VTPDomain,
				NativeVLAN: int32(ciscoDiscoveryInfo.NativeVLAN),
				FullDuplex: ciscoDiscoveryInfo.FullDuplex,
				VLANReply: &types.CDPVLANDialogue{
					ID:   int32(ciscoDiscoveryInfo.VLANReply.ID),
					VLAN: int32(ciscoDiscoveryInfo.VLANReply.VLAN),
				},
				VLANQuery: &types.CDPVLANDialogue{
					ID:   int32(ciscoDiscoveryInfo.VLANQuery.ID),
					VLAN: int32(ciscoDiscoveryInfo.VLANQuery.VLAN),
				},
				PowerConsumption: int32(ciscoDiscoveryInfo.PowerConsumption),
				MTU:              ciscoDiscoveryInfo.MTU,
				ExtendedTrust:    int32(ciscoDiscoveryInfo.ExtendedTrust),
				UntrustedCOS:     int32(ciscoDiscoveryInfo.UntrustedCOS),
				SysName:          ciscoDiscoveryInfo.SysName,
				SysOID:           ciscoDiscoveryInfo.SysOID,
				MgmtAddresses:    mgmtAddresses,
				Location: &types.CDPLocation{
					Type:     int32(ciscoDiscoveryInfo.Location.Type),
					Location: ciscoDiscoveryInfo.Location.Location,
				},
				PowerRequest: &types.CDPPowerDialogue{
					ID:     int32(ciscoDiscoveryInfo.PowerRequest.ID),
					MgmtID: int32(ciscoDiscoveryInfo.PowerRequest.MgmtID),
					Values: ciscoDiscoveryInfo.PowerRequest.Values,
				},
				PowerAvailable: &types.CDPPowerDialogue{
					ID:     int32(ciscoDiscoveryInfo.PowerAvailable.ID),
					MgmtID: int32(ciscoDiscoveryInfo.PowerAvailable.MgmtID),
					Values: ciscoDiscoveryInfo.PowerAvailable.Values,
				},
				SparePairPoe: &types.CDPSparePairPoE{
					PSEFourWire:  ciscoDiscoveryInfo.SparePairPoe.PSEFourWire,
					PDArchShared: ciscoDiscoveryInfo.SparePairPoe.PDArchShared,
					PDRequestOn:  ciscoDiscoveryInfo.SparePairPoe.PDRequestOn,
					PSEOn:        ciscoDiscoveryInfo.SparePairPoe.PSEOn,
				},
				EnergyWise: &types.CDPEnergyWise{
					EncryptedData:  ciscoDiscoveryInfo.EnergyWise.EncryptedData,
					Unknown1:       ciscoDiscoveryInfo.EnergyWise.Unknown1,
					SequenceNumber: ciscoDiscoveryInfo.EnergyWise.SequenceNumber,
					ModelNumber:    ciscoDiscoveryInfo.EnergyWise.ModelNumber,
					Unknown2:       int32(ciscoDiscoveryInfo.EnergyWise.Unknown2),
					HardwareID:     ciscoDiscoveryInfo.EnergyWise.HardwareID,
					SerialNum:      ciscoDiscoveryInfo.EnergyWise.SerialNum,
					Unknown3:       ciscoDiscoveryInfo.EnergyWise.Unknown3,
					Role:           ciscoDiscoveryInfo.EnergyWise.Role,
					Domain:         ciscoDiscoveryInfo.EnergyWise.Domain,
					Name:           ciscoDiscoveryInfo.EnergyWise.Name,
					ReplyUnknown1:  ciscoDiscoveryInfo.EnergyWise.ReplyUnknown1,
					ReplyPort:      ciscoDiscoveryInfo.EnergyWise.ReplyPort,
					ReplyAddress:   ciscoDiscoveryInfo.EnergyWise.ReplyAddress,
					ReplyUnknown2:  ciscoDiscoveryInfo.EnergyWise.ReplyUnknown2,
					ReplyUnknown3:  ciscoDiscoveryInfo.EnergyWise.ReplyUnknown3,
				},
				Unknown: cdvs,
			}
		}

		return nil
	},
)
