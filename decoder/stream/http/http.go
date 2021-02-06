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

package http

import (
	"bytes"

	"github.com/dreadl0ck/netcap/decoder/core"
	"go.uber.org/zap"

	"github.com/dreadl0ck/netcap/decoder"
	decoderconfig "github.com/dreadl0ck/netcap/decoder/config"
	logging "github.com/dreadl0ck/netcap/logger"
	"github.com/dreadl0ck/netcap/types"
)

var httpLog = zap.NewNop()

// Decoder for protocol analysis and writing audit records to disk.
var Decoder = &decoder.StreamDecoder{
	Type:        types.Type_NC_HTTP,
	Name:        "HTTP",
	Description: "The Hypertext Transfer Protocol is powering the world wide web",
	PostInit: func(sd *decoder.StreamDecoder) error {
		var err error
		httpLog, _, err = logging.InitZapLogger(
			decoderconfig.Instance.Out,
			"http",
			decoderconfig.Instance.Debug,
		)
		return err
	},
	CanDecode: func(client, server []byte) bool {
		return containsHTTPProtocolName(server) && containsHTTPMethod(client)
	},
	DeInit: func(sd *decoder.StreamDecoder) error {
		return httpLog.Sync()
	},
	Factory: &httpReader{},
	Typ:     core.All,
}

const keyUnknownParam = "unknown"

var (
	httpMethods = [][]byte{
		[]byte(methodCONNECT),
		[]byte(methodDELETE),
		[]byte(methodGET),
		[]byte(methodHEAD),
		[]byte(methodOPTIONS),
		[]byte(methodPATCH),
		[]byte(methodPOST),
		[]byte(methodPUT),
		[]byte(methodTRACE),
	}
	httpProtocolName = []byte("HTTP")
)

func containsHTTPProtocolName(data []byte) bool {
	return bytes.Contains(data, httpProtocolName)
}

func containsHTTPMethod(data []byte) bool {
	for _, m := range httpMethods {
		if bytes.Contains(data, m) {
			return true
		}
	}
	return false
}
