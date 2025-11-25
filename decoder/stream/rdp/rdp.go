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

package rdp

import (
	"bytes"

	"go.uber.org/zap"

	"github.com/dreadl0ck/netcap/decoder"
	"github.com/dreadl0ck/netcap/decoder/core"
	decoderconfig "github.com/dreadl0ck/netcap/decoder/config"
	logging "github.com/dreadl0ck/netcap/logger"
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
	CanDecode: func(client, server []byte) bool {
		// RDP uses TPKT (starts with 0x03) over TCP
		// Client sends X.224 Connection Request (0xE0)
		// Server responds with X.224 Connection Confirm (0xD0)
		if len(client) >= 11 && client[0] == tpktVersion {
			// Check for X.224 Connection Request
			if client[5] == x224ConnectionRequest {
				return true
			}
			// Check for RDP Cookie pattern "Cookie: mstshash="
			if bytes.Contains(client, []byte("Cookie:")) && bytes.Contains(client, []byte("mstshash=")) {
				return true
			}
		}
		return false
	},
	DeInit: func(sd *decoder.StreamDecoder) error {
		return rdpLog.Sync()
	},
	Factory: &rdpReader{},
	Typ:     core.TCP, // RDP uses TCP port 3389
}

