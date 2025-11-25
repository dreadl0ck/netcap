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

package dnp3

import (
	"go.uber.org/zap"

	"github.com/dreadl0ck/netcap/decoder"
	"github.com/dreadl0ck/netcap/decoder/core"
	decoderconfig "github.com/dreadl0ck/netcap/decoder/config"
	logging "github.com/dreadl0ck/netcap/logger"
	"github.com/dreadl0ck/netcap/types"
)

var dnp3Log = zap.NewNop()

const serviceDNP3 = "DNP3"

// DNP3 start bytes
const (
	dnp3StartByte1 = 0x05
	dnp3StartByte2 = 0x64
)

// Decoder for protocol analysis and writing audit records to disk.
var Decoder = &decoder.StreamDecoder{
	Type:        types.Type_NC_DNP3,
	Name:        serviceDNP3,
	Description: "Distributed Network Protocol 3 (DNP3) is used for ICS/SCADA communications",
	PostInit: func(d *decoder.StreamDecoder) error {
		var err error
		dnp3Log, _, err = logging.InitZapLogger(
			decoderconfig.Instance.Out,
			"dnp3",
			decoderconfig.Instance.Debug,
		)
		return err
	},
	CanDecode: func(client, server []byte) bool {
		// DNP3 frames start with 0x05 0x64 (start bytes)
		return (len(client) >= 10 && client[0] == dnp3StartByte1 && client[1] == dnp3StartByte2) ||
			(len(server) >= 10 && server[0] == dnp3StartByte1 && server[1] == dnp3StartByte2)
	},
	DeInit: func(sd *decoder.StreamDecoder) error {
		return dnp3Log.Sync()
	},
	Factory: &dnp3Reader{},
	Typ:     core.TCP, // DNP3 uses TCP port 20000
}

