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

package http

import (
	"bytes"

	"github.com/dreadl0ck/netcap/decoder/core"
	"go.uber.org/zap"

	"github.com/dreadl0ck/netcap/decoder"
	decoderconfig "github.com/dreadl0ck/netcap/decoder/config"
	logging "github.com/dreadl0ck/netcap/internal/logger"
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
