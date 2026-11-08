/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package ipp

import (
	"bufio"
	"bytes"
	"mime"
	"net/http"
	"strings"

	"go.uber.org/zap"

	"github.com/dreadl0ck/netcap/internal/decoder"
	decoderconfig "github.com/dreadl0ck/netcap/internal/decoder/config"
	"github.com/dreadl0ck/netcap/internal/decoder/core"
	logging "github.com/dreadl0ck/netcap/internal/logger"
	"github.com/dreadl0ck/netcap/types"
)

var ippLog = zap.NewNop()

const serviceIPP = "IPP"

// Decoder for protocol analysis and writing audit records to disk.
var Decoder = &decoder.StreamDecoder{
	Type:        types.Type_NC_IPP,
	Name:        serviceIPP,
	Description: "IPP is the Internet Printing Protocol used for managing print jobs and printer status over HTTP",
	PostInit: func(d *decoder.StreamDecoder) error {
		var err error
		ippLog, _, err = logging.InitZapLogger(
			decoderconfig.Instance.Out,
			"ipp",
			decoderconfig.Instance.Debug,
		)
		return err
	},
	// HTTP request-line and content-type literals.
	Specificity: core.SpecificityStructural + 1,

	CanDecode: func(client, server []byte) bool {
		for _, data := range [][]byte{client, server} {
			if matchesHTTP(data) {
				return true
			}
		}
		return false
	},
	DeInit: func(sd *decoder.StreamDecoder) error {
		return ippLog.Sync()
	},
	Factory: &ippReader{},
	Typ:     core.TCP,
}

// Informational responses precede the final HTTP response and have no body.
// Only walk those headers; a Content-Type literal inside a body is not evidence.
func matchesHTTP(data []byte) bool {
	data = data[:min(len(data), 16384)]
	for interim := 0; len(data) > 0 && interim < 8; interim++ {
		header, rest, complete := bytes.Cut(data, []byte("\r\n\r\n"))
		if !complete {
			return false
		}
		b := bufio.NewReader(bytes.NewReader(data[:len(header)+4]))
		var contentType string
		if bytes.HasPrefix(header, []byte("HTTP/1.")) {
			res, err := http.ReadResponse(b, nil)
			if err != nil {
				return false
			}
			if res.StatusCode >= 100 && res.StatusCode < 200 && res.StatusCode != 101 {
				data = rest
				continue
			}
			contentType = res.Header.Get("Content-Type")
		} else {
			req, err := http.ReadRequest(b)
			if err != nil {
				return false
			}
			contentType = req.Header.Get("Content-Type")
		}
		typ, _, err := mime.ParseMediaType(strings.TrimSpace(contentType))
		return err == nil && typ == "application/ipp"
	}
	return false
}
