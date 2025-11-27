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

// getSTPVersionName returns a human-readable name for the STP version
func getSTPVersionName(version uint8) string {
	switch version {
	case 0:
		return "STP"
	case 2:
		return "RSTP"
	case 3:
		return "MSTP"
	default:
		return "Unknown"
	}
}

// getSTPTypeName returns a human-readable name for the BPDU type
func getSTPTypeName(bpduType uint8) string {
	switch bpduType {
	case 0:
		return "Configuration BPDU"
	case 128:
		return "Topology Change Notification"
	case 2:
		return "RSTP/MSTP BPDU"
	default:
		return "Unknown"
	}
}

// convertSTPSwitchID converts a gopacket STPSwitchID to netcap types
func convertSTPSwitchID(sid layers.STPSwitchID) *types.STPSwitchID {
	return &types.STPSwitchID{
		Priority: int32(sid.Priority),
		SysID:    int32(sid.SysID),
		HwAddr:   sid.HwAddr.String(),
	}
}

var stpDecoder = newGoPacketDecoder(
	types.Type_NC_STP,
	layers.LayerTypeSTP,
	"STP (Spanning Tree Protocol) prevents network loops in Ethernet networks by creating a loop-free logical topology",
	func(layer gopacket.Layer, timestamp int64) proto.Message {
		if stp, ok := layer.(*layers.STP); ok {
			// Check for security-relevant conditions
			isConfigBPDU := stp.Type == 0
			isTCN := stp.Type == 128
			hasZeroPriority := stp.BridgeID.Priority == 0
			// A bridge claims to be root if its BridgeID equals its RouteID (root ID)
			isRootBridge := stp.BridgeID.Priority == stp.RouteID.Priority &&
				stp.BridgeID.SysID == stp.RouteID.SysID &&
				stp.BridgeID.HwAddr.String() == stp.RouteID.HwAddr.String()

			return &types.STP{
				Timestamp:        timestamp,
				ProtocolID:       int32(stp.ProtocolID),
				Version:          int32(stp.Version),
				VersionName:      getSTPVersionName(stp.Version),
				Type:             int32(stp.Type),
				TypeName:         getSTPTypeName(stp.Type),
				TC:               stp.TC,
				TCA:              stp.TCA,
				RootID:           convertSTPSwitchID(stp.RouteID),
				Cost:             stp.Cost,
				BridgeID:         convertSTPSwitchID(stp.BridgeID),
				PortID:           int32(stp.PortID),
				MessageAge:       int32(stp.MessageAge),
				MaxAge:           int32(stp.MaxAge),
				HelloTime:        int32(stp.HelloTime),
				ForwardDelay:     int32(stp.FDelay),
				IsTopologyChange: stp.TC,
				IsConfigBPDU:     isConfigBPDU,
				IsTCN:            isTCN,
				IsRootBridge:     isRootBridge,
				HasZeroPriority:  hasZeroPriority,
			}
		}

		return nil
	},
)

