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
	"github.com/dreadl0ck/gopacket"
	"github.com/dreadl0ck/gopacket/layers"
)

var dot11Encoder = CreateLayerEncoder(types.Type_NC_Dot11, layers.LayerTypeDot11, func(layer gopacket.Layer, timestamp string) proto.Message {
	if dot11, ok := layer.(*layers.Dot11); ok {
		var qos *types.Dot11QOS
		var htcontrol *types.Dot11HTControl
		if dot11.QOS != nil {
			qos = &types.Dot11QOS{
				AckPolicy: int32(dot11.QOS.AckPolicy),
				EOSP:      dot11.QOS.EOSP,
				TID:       int32(dot11.QOS.TID),
				TXOP:      int32(dot11.QOS.TXOP),
			}
		}
		if dot11.HTControl != nil {
			htcontrol = &types.Dot11HTControl{
				ACConstraint: dot11.HTControl.ACConstraint,
				RDGMorePPDU:  dot11.HTControl.RDGMorePPDU,
				VHT: &types.Dot11HTControlVHT{
					MRQ:            dot11.HTControl.VHT.MRQ,
					UnsolicitedMFB: dot11.HTControl.VHT.UnsolicitedMFB,
					MSI:            int32(*dot11.HTControl.VHT.MSI),
					MFB: &types.Dot11HTControlMFB{
						NumSTS: int32(dot11.HTControl.VHT.MFB.NumSTS),
						VHTMCS: int32(dot11.HTControl.VHT.MFB.VHTMCS),
						BW:     int32(dot11.HTControl.VHT.MFB.BW),
						SNR:    int32(dot11.HTControl.VHT.MFB.SNR),
					},
					CompressedMSI:  int32(*dot11.HTControl.VHT.CompressedMSI),
					STBCIndication: dot11.HTControl.VHT.STBCIndication,
					MFSI:           int32(*dot11.HTControl.VHT.MFSI),
					GID:            int32(*dot11.HTControl.VHT.GID),
					CodingType:     int32(*dot11.HTControl.VHT.CodingType),
					FbTXBeamformed: dot11.HTControl.VHT.FbTXBeamformed,
				},
				HT: &types.Dot11HTControlHT{
					LinkAdapationControl: &types.Dot11LinkAdapationControl{
						TRQ:  dot11.HTControl.HT.LinkAdapationControl.TRQ,
						MRQ:  dot11.HTControl.HT.LinkAdapationControl.MRQ,
						MSI:  int32(dot11.HTControl.HT.LinkAdapationControl.MSI),
						MFSI: int32(dot11.HTControl.HT.LinkAdapationControl.MFSI),
						ASEL: &types.Dot11ASEL{
							Command: int32(dot11.HTControl.HT.LinkAdapationControl.ASEL.Command),
							Data:    int32(dot11.HTControl.HT.LinkAdapationControl.ASEL.Data),
						},
						MFB: int32(*dot11.HTControl.HT.LinkAdapationControl.MFB),
					},
					CalibrationPosition: int32(dot11.HTControl.HT.CalibrationPosition),
					CalibrationSequence: int32(dot11.HTControl.HT.CalibrationSequence),
					CSISteering:         int32(dot11.HTControl.HT.CSISteering),
					NDPAnnouncement:     dot11.HTControl.HT.NDPAnnouncement,
					DEI:                 dot11.HTControl.HT.DEI,
				},
			}
		}
		return &types.Dot11{
			Timestamp:      timestamp,
			Type:           int32(dot11.Type),
			Proto:          int32(dot11.Proto),
			Flags:          int32(dot11.Flags),
			DurationID:     int32(dot11.DurationID),
			Address1:       dot11.Address1.String(),
			Address2:       dot11.Address2.String(),
			Address3:       dot11.Address3.String(),
			Address4:       dot11.Address4.String(),
			SequenceNumber: int32(dot11.SequenceNumber),
			FragmentNumber: int32(dot11.FragmentNumber),
			Checksum:       uint32(dot11.Checksum),
			QOS:            qos,
			HTControl:      htcontrol,
		}
	}
	return nil
})
