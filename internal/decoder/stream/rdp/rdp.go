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

package rdp

import (
	"bytes"
	"encoding/binary"

	"go.uber.org/zap"

	"github.com/dreadl0ck/netcap/internal/decoder"
	decoderconfig "github.com/dreadl0ck/netcap/internal/decoder/config"
	"github.com/dreadl0ck/netcap/internal/decoder/core"
	logging "github.com/dreadl0ck/netcap/internal/logger"
	"github.com/dreadl0ck/netcap/types"
)

var rdpLog = zap.NewNop()

const serviceRDP = "RDP"

// TPKT header byte
const tpktVersion = 0x03

// X.224 Connection Request code
const x224ConnectionRequest = 0xE0
const x224ConnectionConfirm = 0xD0

// Decoder for protocol analysis and writing audit records to disk.
var Decoder = &decoder.StreamDecoder{
	Type:        types.Type_NC_RDP,
	Name:        serviceRDP,
	Description: "Remote Desktop Protocol (RDP) is Microsoft's remote access protocol",
	PostInit: func(d *decoder.StreamDecoder) error {
		var err error
		rdpLog, _, err = logging.InitZapLogger(
			decoderconfig.Instance.Out,
			"rdp",
			decoderconfig.Instance.Debug,
		)
		return err
	},
	Specificity: core.SpecificityStructural,

	CanDecode: func(client, server []byte) bool {
		return probeRDP(client) || probeRDP(server)
	},
	DeInit: func(sd *decoder.StreamDecoder) error {
		return rdpLog.Sync()
	},
	Factory: &rdpReader{},
	Typ:     core.TCP, // RDP uses TCP port 3389
}

// A generic X.224 request also belongs to MMS and S7. Require RDP's cookie
// or negotiation structure inside the declared TPKT/X.224 frame.
func probeRDP(data []byte) bool {
	if len(data) < 11 || data[0] != tpktVersion || data[1] != 0 {
		return false
	}
	n := int(binary.BigEndian.Uint16(data[2:4]))
	if n < 11 || int(data[4])+5 != n || data[10] != 0 {
		return false
	}
	request := data[5] == x224ConnectionRequest
	if !request && data[5] != x224ConnectionConfirm {
		return false
	}
	body := data[11:min(n, len(data))]
	cookieSize := 0
	for _, prefix := range []string{"Cookie: mstshash=", "Cookie: msts="} {
		if bytes.HasPrefix(body, []byte(prefix)) {
			cookieSize = len(prefix)
		}
	}
	if request && cookieSize != 0 {
		end := bytes.Index(body, []byte("\r\n"))
		if end < cookieSize {
			return false
		}
		for _, b := range body[cookieSize:end] {
			if b < 0x20 || b > 0x7e {
				return false
			}
		}
		return true
	}
	if len(body) < 8 || binary.LittleEndian.Uint16(body[2:4]) != 8 {
		return false
	}
	protocol := binary.LittleEndian.Uint32(body[4:8])
	if request {
		if body[0] != RDPNegReq || body[1]&^byte(0x0b) != 0 || protocol&^uint32(0x1f) != 0 {
			return false
		}
		if body[1]&8 == 0 {
			return n == 19
		}
		// CORRELATION_INFO is a fixed 36-byte structure after RDP_NEG_REQ.
		return n == 55 && len(body) >= 44 && body[8] == 6 && body[9] == 0 && binary.LittleEndian.Uint16(body[10:12]) == 36 && bytes.Equal(body[28:44], make([]byte, 16))
	}
	if n != 19 {
		return false
	}
	switch body[0] {
	case RDPNegRsp:
		return body[1]&^byte(0x1f) == 0 && (protocol == 0 || protocol == 1 || protocol == 2 || protocol == 4 || protocol == 8 || protocol == 16)
	case RDPNegFailure:
		return body[1] == 0 && protocol >= 1 && protocol <= 6
	}
	return false
}
