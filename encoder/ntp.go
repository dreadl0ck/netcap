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

package encoder

import (
	"github.com/dreadl0ck/gopacket"
	"github.com/dreadl0ck/gopacket/layers"
	"github.com/dreadl0ck/netcap/types"
	"github.com/gogo/protobuf/proto"
)

var ntpEncoder = CreateLayerEncoder(types.Type_NC_NTP, layers.LayerTypeNTP, func(layer gopacket.Layer, timestamp string) proto.Message {
	if ntp, ok := layer.(*layers.NTP); ok {
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
		}
	}
	return nil
})
