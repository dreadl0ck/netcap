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

package bgp

import (
	"bytes"

	"go.uber.org/zap"

	"github.com/dreadl0ck/netcap/decoder"
	"github.com/dreadl0ck/netcap/decoder/core"
	decoderconfig "github.com/dreadl0ck/netcap/decoder/config"
	logging "github.com/dreadl0ck/netcap/logger"
	"github.com/dreadl0ck/netcap/types"
)

var bgpLog = zap.NewNop()

const serviceBGP = "BGP"

// BGP marker - 16 bytes of 0xFF
var bgpMarker = bytes.Repeat([]byte{0xFF}, 16)

// Decoder for protocol analysis and writing audit records to disk.
var Decoder = &decoder.StreamDecoder{
	Type:        types.Type_NC_BGP,
	Name:        serviceBGP,
	Description: "Border Gateway Protocol (BGP) is the protocol for routing between autonomous systems",
	PostInit: func(d *decoder.StreamDecoder) error {
		var err error
		bgpLog, _, err = logging.InitZapLogger(
			decoderconfig.Instance.Out,
			"bgp",
			decoderconfig.Instance.Debug,
		)
		return err
	},
	CanDecode: func(client, server []byte) bool {
		// BGP messages start with 16 bytes of 0xFF marker
		return (len(server) >= 19 && bytes.HasPrefix(server, bgpMarker)) ||
			(len(client) >= 19 && bytes.HasPrefix(client, bgpMarker))
	},
	DeInit: func(sd *decoder.StreamDecoder) error {
		return bgpLog.Sync()
	},
	Factory: &bgpReader{},
	Typ:     core.TCP, // BGP uses TCP port 179
}

