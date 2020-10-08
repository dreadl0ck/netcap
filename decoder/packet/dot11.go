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

var dot11Decoder = newGoPacketDecoder(
	types.Type_NC_Dot11,
	layers.LayerTypeDot11,
	"IEEE 802.11 is part of the IEEE 802 set of local area network protocols, and specifies the set of media access control and physical layer protocols for implementing wireless local area network Wi-Fi",
	func(layer gopacket.Layer, timestamp int64) proto.Message {
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
				var cmsi, msi, mfsi, gid, coding int32
				if dot11.HTControl.VHT != nil {
					if dot11.HTControl.VHT.MSI != nil {
						msi = int32(*dot11.HTControl.VHT.MSI)
					}
					if dot11.HTControl.VHT.MFSI != nil {
						mfsi = int32(*dot11.HTControl.VHT.MFSI)
					}
					if dot11.HTControl.VHT.GID != nil {
						gid = int32(*dot11.HTControl.VHT.GID)
					}
					if dot11.HTControl.VHT.CodingType != nil {
						coding = int32(*dot11.HTControl.VHT.CodingType)
					}
					if dot11.HTControl.VHT.CompressedMSI != nil {
						cmsi = int32(*dot11.HTControl.VHT.CompressedMSI)
					}
				}

				var vht *types.Dot11HTControlVHT
				if dot11.HTControl.VHT != nil {
					vht = &types.Dot11HTControlVHT{
						MRQ:            dot11.HTControl.VHT.MRQ,
						UnsolicitedMFB: dot11.HTControl.VHT.UnsolicitedMFB,
						MSI:            msi,
						MFB: &types.Dot11HTControlMFB{
							NumSTS: int32(dot11.HTControl.VHT.MFB.NumSTS),
							VHTMCS: int32(dot11.HTControl.VHT.MFB.VHTMCS),
							BW:     int32(dot11.HTControl.VHT.MFB.BW),
							SNR:    int32(dot11.HTControl.VHT.MFB.SNR),
						},
						CompressedMSI:  cmsi,
						STBCIndication: dot11.HTControl.VHT.STBCIndication,
						MFSI:           mfsi,
						GID:            gid,
						CodingType:     coding,
						FbTXBeamformed: dot11.HTControl.VHT.FbTXBeamformed,
					}
				}

				var ht *types.Dot11HTControlHT
				if dot11.HTControl.HT != nil {
					var mfb int32
					var lac *types.Dot11LinkAdapationControl
					if dot11.HTControl.HT.LinkAdapationControl != nil {
						if dot11.HTControl.HT.LinkAdapationControl.MFB != nil {
							mfb = int32(*dot11.HTControl.HT.LinkAdapationControl.MFB)
						}
						var asel *types.Dot11ASEL
						if dot11.HTControl.HT.LinkAdapationControl.ASEL != nil {
							asel = &types.Dot11ASEL{
								Command: int32(dot11.HTControl.HT.LinkAdapationControl.ASEL.Command),
								Data:    int32(dot11.HTControl.HT.LinkAdapationControl.ASEL.Data),
							}
						}
						lac = &types.Dot11LinkAdapationControl{
							TRQ:  dot11.HTControl.HT.LinkAdapationControl.TRQ,
							MRQ:  dot11.HTControl.HT.LinkAdapationControl.MRQ,
							MSI:  int32(dot11.HTControl.HT.LinkAdapationControl.MSI),
							MFSI: int32(dot11.HTControl.HT.LinkAdapationControl.MFSI),
							ASEL: asel,
							MFB:  mfb,
						}
					}
					ht = &types.Dot11HTControlHT{
						LinkAdapationControl: lac,
						CalibrationPosition:  int32(dot11.HTControl.HT.CalibrationPosition),
						CalibrationSequence:  int32(dot11.HTControl.HT.CalibrationSequence),
						CSISteering:          int32(dot11.HTControl.HT.CSISteering),
						NDPAnnouncement:      dot11.HTControl.HT.NDPAnnouncement,
						DEI:                  dot11.HTControl.HT.DEI,
					}
				}

				htcontrol = &types.Dot11HTControl{
					ACConstraint: dot11.HTControl.ACConstraint,
					RDGMorePPDU:  dot11.HTControl.RDGMorePPDU,
					VHT:          vht,
					HT:           ht,
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
				Checksum:       dot11.Checksum,
				QOS:            qos,
				HTControl:      htcontrol,
			}
		}

		return nil
	},
)
