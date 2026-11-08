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
			for interim := 0; interim < 8; interim++ {
				header, remainder, complete := bytes.Cut(data, []byte("\r\n\r\n"))
				if len(header) > 16384 {
					break
				}
				for _, line := range strings.Split(string(header), "\r\n") {
					name, value, ok := strings.Cut(line, ":")
					if ok && strings.EqualFold(name, "Content-Type") {
						typ, _, err := mime.ParseMediaType(strings.TrimSpace(value))
						if err == nil && typ == "application/ipp" {
							return true
						}
					}
				}
				if !complete || !bytes.HasPrefix(header, []byte("HTTP/")) {
					break
				}
				response, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(data[:len(header)+4])), nil)
				if err != nil || response.StatusCode < 100 || response.StatusCode >= 200 || response.StatusCode == 101 {
					break
				}
				data = remainder
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
