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

var ciscoDiscoveryInfoEncoder = CreateLayerEncoder(types.Type_NC_CiscoDiscoveryInfo, layers.LayerTypeCiscoDiscoveryInfo, func(layer gopacket.Layer, timestamp string) proto.Message {
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
				Value:  []byte(v.Value),
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
			DeviceID:  string(ciscoDiscoveryInfo.DeviceID),
			Addresses: addresses,
			PortID:    string(ciscoDiscoveryInfo.PortID),
			Capabilities: &types.CDPCapabilities{
				L3Router:        bool(ciscoDiscoveryInfo.Capabilities.L3Router),
				TBBridge:        bool(ciscoDiscoveryInfo.Capabilities.TBBridge),
				SPBridge:        bool(ciscoDiscoveryInfo.Capabilities.SPBridge),
				L2Switch:        bool(ciscoDiscoveryInfo.Capabilities.L2Switch),
				IsHost:          bool(ciscoDiscoveryInfo.Capabilities.IsHost),
				IGMPFilter:      bool(ciscoDiscoveryInfo.Capabilities.IGMPFilter),
				L1Repeater:      bool(ciscoDiscoveryInfo.Capabilities.L1Repeater),
				IsPhone:         bool(ciscoDiscoveryInfo.Capabilities.IsPhone),
				RemotelyManaged: bool(ciscoDiscoveryInfo.Capabilities.RemotelyManaged),
			},
			Version:    string(ciscoDiscoveryInfo.Version),
			Platform:   string(ciscoDiscoveryInfo.Platform),
			IPPrefixes: ipNets,
			VTPDomain:  string(ciscoDiscoveryInfo.VTPDomain),
			NativeVLAN: int32(ciscoDiscoveryInfo.NativeVLAN),
			FullDuplex: bool(ciscoDiscoveryInfo.FullDuplex),
			VLANReply: &types.CDPVLANDialogue{
				ID:   int32(ciscoDiscoveryInfo.VLANReply.ID),
				VLAN: int32(ciscoDiscoveryInfo.VLANReply.VLAN),
			},
			VLANQuery: &types.CDPVLANDialogue{
				ID:   int32(ciscoDiscoveryInfo.VLANQuery.ID),
				VLAN: int32(ciscoDiscoveryInfo.VLANQuery.VLAN),
			},
			PowerConsumption: int32(ciscoDiscoveryInfo.PowerConsumption),
			MTU:              uint32(ciscoDiscoveryInfo.MTU),
			ExtendedTrust:    int32(ciscoDiscoveryInfo.ExtendedTrust),
			UntrustedCOS:     int32(ciscoDiscoveryInfo.UntrustedCOS),
			SysName:          string(ciscoDiscoveryInfo.SysName),
			SysOID:           string(ciscoDiscoveryInfo.SysOID),
			MgmtAddresses:    mgmtAddresses,
			Location: &types.CDPLocation{
				Type:     int32(ciscoDiscoveryInfo.Location.Type),
				Location: string(ciscoDiscoveryInfo.Location.Location),
			},
			PowerRequest: &types.CDPPowerDialogue{
				ID:     int32(ciscoDiscoveryInfo.PowerRequest.ID),
				MgmtID: int32(ciscoDiscoveryInfo.PowerRequest.MgmtID),
				Values: []uint32(ciscoDiscoveryInfo.PowerRequest.Values),
			},
			PowerAvailable: &types.CDPPowerDialogue{
				ID:     int32(ciscoDiscoveryInfo.PowerAvailable.ID),
				MgmtID: int32(ciscoDiscoveryInfo.PowerAvailable.MgmtID),
				Values: []uint32(ciscoDiscoveryInfo.PowerAvailable.Values),
			},
			SparePairPoe: &types.CDPSparePairPoE{
				PSEFourWire:  bool(ciscoDiscoveryInfo.SparePairPoe.PSEFourWire),
				PDArchShared: bool(ciscoDiscoveryInfo.SparePairPoe.PDArchShared),
				PDRequestOn:  bool(ciscoDiscoveryInfo.SparePairPoe.PDRequestOn),
				PSEOn:        bool(ciscoDiscoveryInfo.SparePairPoe.PSEOn),
			},
			EnergyWise: &types.CDPEnergyWise{
				EncryptedData:  []byte(ciscoDiscoveryInfo.EnergyWise.EncryptedData),
				Unknown1:       uint32(ciscoDiscoveryInfo.EnergyWise.Unknown1),
				SequenceNumber: uint32(ciscoDiscoveryInfo.EnergyWise.SequenceNumber),
				ModelNumber:    string(ciscoDiscoveryInfo.EnergyWise.ModelNumber),
				Unknown2:       int32(ciscoDiscoveryInfo.EnergyWise.Unknown2),
				HardwareID:     string(ciscoDiscoveryInfo.EnergyWise.HardwareID),
				SerialNum:      string(ciscoDiscoveryInfo.EnergyWise.SerialNum),
				Unknown3:       []byte(ciscoDiscoveryInfo.EnergyWise.Unknown3),
				Role:           string(ciscoDiscoveryInfo.EnergyWise.Role),
				Domain:         string(ciscoDiscoveryInfo.EnergyWise.Domain),
				Name:           string(ciscoDiscoveryInfo.EnergyWise.Name),
				ReplyUnknown1:  []byte(ciscoDiscoveryInfo.EnergyWise.ReplyUnknown1),
				ReplyPort:      []byte(ciscoDiscoveryInfo.EnergyWise.ReplyPort),
				ReplyAddress:   []byte(ciscoDiscoveryInfo.EnergyWise.ReplyAddress),
				ReplyUnknown2:  []byte(ciscoDiscoveryInfo.EnergyWise.ReplyUnknown2),
				ReplyUnknown3:  []byte(ciscoDiscoveryInfo.EnergyWise.ReplyUnknown3),
			},
			Unknown: cdvs,
		}
	}
	return nil
})
