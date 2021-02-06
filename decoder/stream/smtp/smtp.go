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

package smtp

import (
	"bytes"
	"strconv"

	"github.com/dreadl0ck/netcap/decoder/core"

	"go.uber.org/zap"

	"github.com/dreadl0ck/netcap/decoder"
	decoderconfig "github.com/dreadl0ck/netcap/decoder/config"
	logging "github.com/dreadl0ck/netcap/logger"
	"github.com/dreadl0ck/netcap/types"
)

var (
	smtpLog               *zap.Logger
	smtpLogSugared        *zap.SugaredLogger
	smtpServiceReadyBytes = []byte(strconv.Itoa(smtpServiceReady))
	smtpName              = []byte("SMTP")
)

// Decoder for protocol analysis and writing audit records to disk.
var Decoder = &decoder.StreamDecoder{
	Type:        types.Type_NC_SMTP,
	Name:        serviceSMTP,
	Description: "The Simple Mail Transfer Protocol is a communication protocol for electronic mail transmission",
	PostInit: func(d *decoder.StreamDecoder) (err error) {
		smtpLog, _, err = logging.InitZapLogger(
			decoderconfig.Instance.Out,
			"mail",
			decoderconfig.Instance.Debug,
		)

		if err != nil {
			return err
		}

		smtpLogSugared = smtpLog.Sugar()

		return nil
	},
	CanDecode: func(client, server []byte) bool {
		return bytes.HasPrefix(server, smtpServiceReadyBytes) && bytes.Contains(server, smtpName)
	},
	DeInit: func(sd *decoder.StreamDecoder) error {
		return smtpLog.Sync()
	},
	Factory: &smtpReader{},
	Typ:     core.TCP,
}
