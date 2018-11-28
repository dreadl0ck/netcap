/*
 * NETCAP - Network Capture Toolkit
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

var SCTPEncoder = CreateLayerEncoder(types.Type_NC_SCTP, layers.LayerTypeSCTP, func(layer gopacket.Layer, timestamp string) proto.Message {
	if sctp, ok := layer.(*layers.SCTP); ok {
		return &types.SCTP{
			Timestamp:       timestamp,
			Checksum:        sctp.Checksum,
			DstPort:         uint32(sctp.DstPort),
			SrcPort:         uint32(sctp.SrcPort),
			VerificationTag: sctp.VerificationTag,
		}
	}
	return nil
})
