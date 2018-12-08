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

var dhcpv4Encoder = CreateLayerEncoder(types.Type_NC_DHCPv4, layers.LayerTypeDHCPv4, func(layer gopacket.Layer, timestamp string) proto.Message {
	if dhcp4, ok := layer.(*layers.DHCPv4); ok {
		var opts []*types.DHCPOption
		for _, o := range dhcp4.Options {
			opts = append(opts, &types.DHCPOption{
				Data:   o.Data,
				Length: int32(o.Length),
				Type:   int32(o.Type),
			})
		}

		return &types.DHCPv4{
			Timestamp:    timestamp,
			Operation:    int32(dhcp4.Operation),
			HardwareType: int32(dhcp4.HardwareType),
			HardwareLen:  int32(dhcp4.HardwareLen),
			HardwareOpts: int32(dhcp4.HardwareOpts),
			Xid:          uint32(dhcp4.Xid),
			Secs:         int32(dhcp4.Secs),
			Flags:        int32(dhcp4.Flags),
			ClientIP:     dhcp4.ClientIP.String(),
			YourClientIP: dhcp4.YourClientIP.String(),
			NextServerIP: dhcp4.NextServerIP.String(),
			RelayAgentIP: dhcp4.RelayAgentIP.String(),
			ClientHWAddr: dhcp4.ClientHWAddr.String(),
			ServerName:   []byte(dhcp4.ServerName),
			File:         []byte(dhcp4.File),
			Options:      opts,
		}
	}
	return nil
})
