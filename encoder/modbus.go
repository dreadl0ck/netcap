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
	"github.com/golang/protobuf/proto"
)

var modbusEncoder = CreateLayerEncoder(types.Type_NC_Modbus, layers.LayerTypeModbus, func(layer gopacket.Layer, timestamp string) proto.Message {
	if m, ok := layer.(*layers.Modbus); ok {
		var payload []byte
		if CapturePayload {
			payload = m.ReqResp
		}
		return &types.Modbus{
			Timestamp:     timestamp,
			TransactionID: int32(m.TransactionID),
			ProtocolID:    int32(m.ProtocolID),
			Length:        int32(m.Length),
			UnitID:        int32(m.UnitID),
			Payload:       payload,
			Exception:     m.Exception,
			FunctionCode:  int32(m.FunctionCode),
		}
	}
	return nil
})
