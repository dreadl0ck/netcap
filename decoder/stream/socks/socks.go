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

package socks

import (
	"go.uber.org/zap"

	"github.com/dreadl0ck/netcap/decoder"
	"github.com/dreadl0ck/netcap/decoder/core"
	decoderconfig "github.com/dreadl0ck/netcap/decoder/config"
	logging "github.com/dreadl0ck/netcap/logger"
	"github.com/dreadl0ck/netcap/types"
)

var socksLog = zap.NewNop()

const serviceSOCKS = "SOCKS"

// Decoder for protocol analysis and writing audit records to disk.
var Decoder = &decoder.StreamDecoder{
	Type:        types.Type_NC_SOCKS,
	Name:        serviceSOCKS,
	Description: "SOCKS is a proxy protocol for routing packets between client and server through a proxy",
	PostInit: func(d *decoder.StreamDecoder) error {
		var err error
		socksLog, _, err = logging.InitZapLogger(
			decoderconfig.Instance.Out,
			"socks",
			decoderconfig.Instance.Debug,
		)
		return err
	},
	CanDecode: func(client, server []byte) bool {
		// SOCKS5 handshake starts with version byte (0x05) and number of auth methods
		if len(client) >= 3 && client[0] == 0x05 && int(client[1])+2 <= len(client) {
			return true
		}
		// SOCKS4 request starts with version byte (0x04) and command byte
		if len(client) >= 9 && client[0] == 0x04 && (client[1] == 0x01 || client[1] == 0x02) {
			return true
		}
		return false
	},
	DeInit: func(sd *decoder.StreamDecoder) error {
		return socksLog.Sync()
	},
	Factory: &socksReader{},
	Typ:     core.TCP, // SOCKS uses TCP port 1080
}

