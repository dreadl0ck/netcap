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
	"bytes"

	"go.uber.org/zap"

	"github.com/dreadl0ck/netcap/decoder"
	decoderconfig "github.com/dreadl0ck/netcap/decoder/config"
	"github.com/dreadl0ck/netcap/decoder/core"
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
	CanDecode: func(client, server []byte) bool {
		// Check for IPP indicators in client or server data
		if len(client) > 0 {
			// Check for HTTP POST to IPP endpoints
			if bytes.Contains(client, []byte("POST /ipp")) ||
				bytes.Contains(client, []byte("POST /printers")) {
				return true
			}
			// Check for application/ipp content type
			if bytes.Contains(client, []byte("application/ipp")) {
				return true
			}
		}
		// Check for application/ipp content type in server response
		if len(server) > 0 {
			if bytes.Contains(server, []byte("application/ipp")) {
				return true
			}
			// Check for IPP version bytes in response body after HTTP headers
			if idx := bytes.Index(server, []byte("\r\n\r\n")); idx >= 0 {
				body := server[idx+4:]
				if len(body) >= 4 && (body[0] == 0x01 || body[0] == 0x02) && body[1] <= 0x01 {
					return true
				}
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
