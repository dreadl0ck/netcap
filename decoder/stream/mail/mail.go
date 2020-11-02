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

package mail

import (
	"log"
	"sync/atomic"

	"go.uber.org/zap"

	"github.com/dreadl0ck/netcap/decoder"
	decoderconfig "github.com/dreadl0ck/netcap/decoder/config"
	logging "github.com/dreadl0ck/netcap/logger"
	"github.com/dreadl0ck/netcap/types"
)

var mailLog = zap.NewNop()

// Decoder for protocol analysis and writing audit records to disk.
var Decoder = &decoder.AbstractDecoder{
	Type:        types.Type_NC_Mail,
	Name:        "Mail",
	Description: "Email messages collected from the network traffic",
	PostInit: func(d *decoder.AbstractDecoder) error {
		var err error
		mailLog, _, err = logging.InitZapLogger(
			decoderconfig.Instance.Out,
			"mail",
			decoderconfig.Instance.Debug,
		)
		return err
	},
	DeInit: func(sd *decoder.AbstractDecoder) error {
		return mailLog.Sync()
	},
}

// WriteMail writes an email audit record to disk.
func WriteMail(d *types.Mail) {
	if decoderconfig.Instance.ExportMetrics {
		d.Inc()
	}

	atomic.AddInt64(&Decoder.NumRecordsWritten, 1)

	err := Decoder.Writer.Write(d)
	if err != nil {
		log.Fatal("failed to write proto: ", err)
	}
}
