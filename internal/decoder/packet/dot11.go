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
	"bytes"
	"encoding/binary"
	"github.com/dreadl0ck/netcap/internal/utils"

	"github.com/gogo/protobuf/proto"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	"github.com/dreadl0ck/netcap/types"
)

// dot11TypeNames maps Dot11 frame types to names
var dot11TypeNames = map[layers.Dot11Type]string{
	layers.Dot11TypeMgmt:     "Management",
	layers.Dot11TypeCtrl:     "Control",
	layers.Dot11TypeData:     "Data",
	layers.Dot11TypeReserved: "Reserved",
}

// dot11SubtypeNames maps management frame subtypes to names
var dot11SubtypeNames = map[layers.Dot11Type]string{
	layers.Dot11TypeData:                  "Data",
	layers.Dot11TypeDataCFAck:             "Data CF Ack",
	layers.Dot11TypeDataCFPoll:            "Data CF Poll",
	layers.Dot11TypeDataCFAckPoll:         "Data CF Ack Poll",
	layers.Dot11TypeDataNull:              "Null Data",
	layers.Dot11TypeDataQOSData:           "QoS Data",
	layers.Dot11TypeDataQOSNull:           "QoS Null",
	layers.Dot11TypeCtrlAck:               "ACK",
	layers.Dot11TypeCtrlCTS:               "CTS",
	layers.Dot11TypeCtrlRTS:               "RTS",
	layers.Dot11TypeMgmtAssociationReq:    "Association Request",
	layers.Dot11TypeMgmtAssociationResp:   "Association Response",
	layers.Dot11TypeMgmtReassociationReq:  "Reassociation Request",
	layers.Dot11TypeMgmtReassociationResp: "Reassociation Response",
	layers.Dot11TypeMgmtProbeReq:          "Probe Request",
	layers.Dot11TypeMgmtProbeResp:         "Probe Response",
	layers.Dot11TypeMgmtBeacon:            "Beacon",
	layers.Dot11TypeMgmtATIM:              "ATIM",
	layers.Dot11TypeMgmtDisassociation:    "Disassociation",
	layers.Dot11TypeMgmtAuthentication:    "Authentication",
	layers.Dot11TypeMgmtDeauthentication:  "Deauthentication",
	layers.Dot11TypeMgmtAction:            "Action",
	layers.Dot11TypeMgmtActionNoAck:       "Action No Ack",
}

// dot11ReasonCodes maps Dot11 reason codes to names
var dot11ReasonCodeNames = map[uint16]string{
	1:  "Unspecified",
	2:  "Previous auth not valid",
	3:  "Deauth leaving",
	4:  "Disassoc due to inactivity",
	5:  "Disassoc AP busy",
	6:  "Class 2 frame from nonauth STA",
	7:  "Class 3 frame from nonassoc STA",
	8:  "Disassoc STA leaving",
	9:  "STA not authenticated with assoc STA",
	10: "Disassoc power cap bad",
	11: "Disassoc supp chan bad",
	13: "Invalid IE",
	14: "MIC failure",
	15: "4-way handshake timeout",
	16: "Group key handshake timeout",
	17: "IE in 4-way differs",
	18: "Invalid group cipher",
	19: "Invalid pairwise cipher",
	20: "Invalid AKMP",
	21: "Unsupported RSN IE version",
	22: "Invalid RSN IE cap",
	23: "802.1X auth failed",
	24: "Cipher suite rejected",
}

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

			// Get frame type name (Management, Control, Data)
			frameType := dot11.Type.MainType()
			typeName := dot11TypeNames[frameType]
			if typeName == "" {
				typeName = "Unknown"
			}

			// Get subtype name (for management frames)
			subtypeName := dot11SubtypeNames[dot11.Type]
			if subtypeName == "" {
				subtypeName = "Unknown"
			}

			// Check for deauthentication and disassociation (attack indicators)
			isDeauth := dot11.Type == layers.Dot11TypeMgmtDeauthentication
			isDisassoc := dot11.Type == layers.Dot11TypeMgmtDisassociation

			// Extract reason code for deauth/disassoc frames
			// The reason code is a 2-byte little-endian value at the start of the frame body
			var reasonCode int32
			var reasonCodeName string
			if (isDeauth || isDisassoc) && !dot11.Flags.WEP() && len(dot11.Payload) >= 2 {
				reasonCode = int32(binary.LittleEndian.Uint16(dot11.Payload[:2]))
				reasonCodeName = dot11ReasonCodeNames[uint16(reasonCode)]
				if reasonCodeName == "" {
					reasonCodeName = "Unknown"
				}
			}

			// Check retry flag (could indicate jamming if excessive)
			isRetry := (dot11.Flags & layers.Dot11FlagsRetry) != 0

			record := &types.Dot11{
				Timestamp:          timestamp,
				Type:               int32(dot11.Type),
				Proto:              int32(dot11.Proto),
				Flags:              int32(dot11.Flags),
				DurationID:         int32(dot11.DurationID),
				Address1:           dot11.Address1.String(),
				Address2:           dot11.Address2.String(),
				Address3:           dot11.Address3.String(),
				Address4:           dot11.Address4.String(),
				SequenceNumber:     int32(dot11.SequenceNumber),
				FragmentNumber:     int32(dot11.FragmentNumber),
				Checksum:           dot11.Checksum,
				QOS:                qos,
				HTControl:          htcontrol,
				TypeName:           typeName,
				SubtypeName:        subtypeName,
				IsDeauthentication: isDeauth,
				IsDisassociation:   isDisassoc,
				ReasonCode:         reasonCode,
				ReasonCodeName:     reasonCodeName,
				IsRetry:            isRetry,
			}
			populateDot11Metadata(dot11, record)
			return record
		}

		return nil
	},
)

func populateDot11Metadata(wire *layers.Dot11, record *types.Dot11) {
	body := wire.Payload
	if wire.Flags.WEP() {
		if len(body) >= 4 && body[3]&0x20 == 0 {
			record.WEPIV = bytes.Clone(body[:3])
			record.WEPKeyID = int32(body[3] >> 6)
		}
		return
	}
	skip := 0
	switch wire.Type {
	case layers.Dot11TypeMgmtBeacon, layers.Dot11TypeMgmtProbeResp:
		skip = 12
	case layers.Dot11TypeMgmtAssociationReq:
		skip = 4
	case layers.Dot11TypeMgmtAssociationResp, layers.Dot11TypeMgmtReassociationResp, layers.Dot11TypeMgmtAuthentication:
		skip = 6
	case layers.Dot11TypeMgmtReassociationReq:
		skip = 10
	case layers.Dot11TypeMgmtProbeReq:
	default:
		return
	}
	if len(body) < skip {
		record.IEsTruncated = true
		return
	}
	body = body[skip:]
	ssidSeen := false
	for len(body) > 0 {
		if len(record.InformationElements) >= 256 || len(body) < 2 {
			record.IEsTruncated = true
			break
		}
		size := int(body[1])
		available := min(size, len(body)-2)
		element := &types.Dot11InformationElement{ID: uint32(body[0]), Data: bytes.Clone(body[2 : 2+available]), Truncated: size > available}
		record.InformationElements = append(record.InformationElements, element)
		if element.ID == 0 && !ssidSeen {
			record.SSIDRaw = bytes.Clone(element.Data)
			record.SSID = utils.PrintableBytes(element.Data)
			ssidSeen = true
		}
		if element.Truncated {
			record.IEsTruncated = true
			break
		}
		body = body[2+size:]
	}
}
