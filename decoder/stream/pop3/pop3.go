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

package pop3

import (
	"bytes"

	"github.com/dreadl0ck/netcap/decoder/core"
	"go.uber.org/zap"

	"github.com/dreadl0ck/netcap/decoder"
	decoderconfig "github.com/dreadl0ck/netcap/decoder/config"
	logging "github.com/dreadl0ck/netcap/logger"
	"github.com/dreadl0ck/netcap/types"
)

// Decoder for protocol analysis and writing audit records to disk.
var Decoder = &decoder.StreamDecoder{
	Type:        types.Type_NC_POP3,
	Name:        servicePOP3,
	Description: "The POP3 protocol is used to fetch emails from a mail server",
	PostInit: func(sd *decoder.StreamDecoder) (err error) {
		pop3Log, _, err = logging.InitZapLogger(
			decoderconfig.Instance.Out,
			"pop3",
			decoderconfig.Instance.Debug,
		)
		if err != nil {
			return err
		}
		pop3LogSugared = pop3Log.Sugar()
		return nil
	},
	CanDecode: func(client, server []byte) bool {
		return bytes.Contains(server, pop3Ident)
	},
	DeInit: func(sd *decoder.StreamDecoder) error {
		return pop3Log.Sync()
	},
	Factory: &pop3Reader{},
	Typ:     core.TCP,
}

var (
	pop3Ident      = []byte("POP server ready")
	servicePOP3    = "POP3"
	pop3Log        *zap.Logger
	pop3LogSugared *zap.SugaredLogger
)
