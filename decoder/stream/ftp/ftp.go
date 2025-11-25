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

package ftp

import (
	"github.com/dreadl0ck/netcap/decoder"
	"github.com/dreadl0ck/netcap/decoder/core"
	decoderconfig "github.com/dreadl0ck/netcap/decoder/config"
	logging "github.com/dreadl0ck/netcap/logger"
	"github.com/dreadl0ck/netcap/types"
	"go.uber.org/zap"
)

var ftpLog = zap.NewNop()

// Decoder for FTP protocol analysis
var Decoder = &decoder.StreamDecoder{
	Type:        types.Type_NC_FTP,
	Name:        "FTP",
	Description: "File Transfer Protocol - control and data channels",
	PostInit: func(sd *decoder.StreamDecoder) error {
		var err error
		ftpLog, _, err = logging.InitZapLogger(
			decoderconfig.Instance.Out,
			"ftp",
			decoderconfig.Instance.Debug,
		)
		if err != nil {
			return err
		}
		// Initialize connection tracking
		initConnectionTracker()
		return nil
	},
	CanDecode: func(client, server []byte) bool {
		// FTP server starts with 220
		if len(server) > 3 && server[0] == '2' && server[1] == '2' && server[2] == '0' {
			return true
		}
		return false
	},
	DeInit: func(sd *decoder.StreamDecoder) error {
		return ftpLog.Sync()
	},
	Factory: &ftpReader{},
	Typ:     core.TCP,
}

