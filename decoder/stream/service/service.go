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

package service

import (
	"sync/atomic"

	"github.com/dreadl0ck/netcap/decoder"
	decoderconfig "github.com/dreadl0ck/netcap/decoder/config"
	logging "github.com/dreadl0ck/netcap/logger"
	"github.com/dreadl0ck/netcap/types"
	"go.uber.org/zap"
)

var (
	serviceLog        *zap.Logger
	serviceLogSugared *zap.SugaredLogger
)

// Decoder for protocol analysis and writing audit records to disk.
var Decoder = &decoder.AbstractDecoder{
	Type:        types.Type_NC_Service,
	Name:        "Service",
	Description: "A network service",
	PostInit: func(d *decoder.AbstractDecoder) error {
		var err error
		serviceLog, _, err = logging.InitZapLogger(
			decoderconfig.Instance.Out,
			"service",
			decoderconfig.Instance.Debug,
		)
		if err != nil {
			return err
		}

		serviceLogSugared = serviceLog.Sugar()

		return initServiceProbes()
	},
	DeInit: func(e *decoder.AbstractDecoder) error {
		// flush writer
		var err error
		for _, item := range Store.Items {
			item.Lock()
			err = e.Writer.Write(item.Service)
			if err != nil {
				serviceLog.Error("failed to flush service audit record", zap.Error(err))
			}
			item.Unlock()

			atomic.AddInt64(&e.NumRecordsWritten, 1)
		}

		return serviceLog.Sync()
	},
}
