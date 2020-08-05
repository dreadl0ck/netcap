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

package decoder

import (
	"github.com/dreadl0ck/gopacket"
	"github.com/dreadl0ck/gopacket/layers"
	"github.com/gogo/protobuf/proto"

	"github.com/dreadl0ck/netcap/types"
)

var smtpDecoder = NewGoPacketDecoder(
	types.Type_NC_SMTP,
	layers.LayerTypeSMTP,
	"The Simple Mail Transfer Protocol is a communication protocol for electronic mail transmission",
	func(layer gopacket.Layer, timestamp string) proto.Message {
		if smtp, ok := layer.(*layers.SMTP); ok {
			var responses []*types.SMTPResponse
			for _, r := range smtp.ResponseLines {
				responses = append(responses, &types.SMTPResponse{
					ResponseCode: int32(r.ResponseCode),
					Parameter:    r.Parameter,
				})
			}
			return &types.SMTP{
				Timestamp:     timestamp,
				IsEncrypted:   smtp.IsEncrypted,
				IsResponse:    smtp.IsResponse,
				ResponseLines: responses,
				Command: &types.SMTPCommand{
					Command:   int32(smtp.Command.Command),
					Parameter: smtp.Command.Parameter,
				},
			}
		}
		return nil
	},
)
