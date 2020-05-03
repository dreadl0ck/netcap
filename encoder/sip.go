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
	"strings"

	"github.com/dreadl0ck/gopacket"
	"github.com/dreadl0ck/gopacket/layers"
	"github.com/dreadl0ck/netcap/types"
	"github.com/gogo/protobuf/proto"
)

var sipEncoder = CreateLayerEncoder(types.Type_NC_SIP, layers.LayerTypeSIP, func(layer gopacket.Layer, timestamp string) proto.Message {
	if sip, ok := layer.(*layers.SIP); ok {
		headers := []string{}
		for k, v := range sip.Headers {
			headers = append(headers, k+":"+strings.Join(v, ","))
		}
		return &types.SIP{
			Timestamp:      timestamp,
			Version:        int32(sip.Version),
			Method:         int32(sip.Method),
			Headers:        headers,
			IsResponse:     bool(sip.IsResponse),
			ResponseCode:   int32(sip.ResponseCode),
			ResponseStatus: string(sip.ResponseStatus),
		}
	}
	return nil
})
