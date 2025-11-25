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
	"encoding/binary"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gogo/protobuf/proto"

	"github.com/dreadl0ck/netcap/types"
)

// ntpModeNames maps NTP mode values to names
var ntpModeNames = map[layers.NTPMode]string{
	0: "Reserved",
	1: "Symmetric Active",
	2: "Symmetric Passive",
	3: "Client",
	4: "Server",
	5: "Broadcast",
	6: "Control",
	7: "Private",
}

var ntpDecoder = newGoPacketDecoder(
	types.Type_NC_NTP,
	layers.LayerTypeNTP,
	"The Network Time Protocol is a networking protocol for clock synchronization between computer systems over packet-switched, variable-latency data networks",
	func(layer gopacket.Layer, timestamp int64) proto.Message {
		if ntp, ok := layer.(*layers.NTP); ok {
			// Get mode name
			modeName := ntpModeNames[ntp.Mode]
			if modeName == "" {
				modeName = "Unknown"
			}

			// Mode 6 is control message (ntpq, ntpdc)
			isControlMessage := ntp.Mode == 6

			// Mode 7 is private/implementation-specific (monlist amplification attack)
			isPrivateMode := ntp.Mode == 7

			// Stratum 0 is KoD (Kiss of Death) or unspecified
			isKissOfDeath := ntp.Stratum == 0

			// For stratum 0-1, ReferenceID is ASCII string
			var refIDStr string
			if ntp.Stratum <= 1 {
				refBytes := make([]byte, 4)
				binary.BigEndian.PutUint32(refBytes, uint32(ntp.ReferenceID))
				// Filter out null bytes
				for _, b := range refBytes {
					if b >= 32 && b < 127 {
						refIDStr += string(b)
					}
				}
			}

			return &types.NTP{
				Timestamp:          timestamp,
				LeapIndicator:      int32(ntp.LeapIndicator),
				Version:            int32(ntp.Version),
				Mode:               int32(ntp.Mode),
				Stratum:            int32(ntp.Stratum),
				Poll:               int32(ntp.Poll),
				Precision:          int32(ntp.Precision),
				RootDelay:          uint32(ntp.RootDelay),
				RootDispersion:     uint32(ntp.RootDispersion),
				ReferenceID:        uint32(ntp.ReferenceID),
				ReferenceTimestamp: uint64(ntp.ReferenceTimestamp),
				OriginTimestamp:    uint64(ntp.OriginTimestamp),
				ReceiveTimestamp:   uint64(ntp.ReceiveTimestamp),
				TransmitTimestamp:  uint64(ntp.TransmitTimestamp),
				ExtensionBytes:     ntp.ExtensionBytes,
				ModeName:           modeName,
				IsControlMessage:   isControlMessage,
				IsPrivateMode:      isPrivateMode,
				IsKissOfDeath:      isKissOfDeath,
				ReferenceIDStr:     refIDStr,
			}
		}

		return nil
	},
)
