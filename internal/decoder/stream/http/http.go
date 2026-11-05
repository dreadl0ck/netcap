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
	"net/http"
	"net/url"
	"strings"

	"github.com/dreadl0ck/netcap/internal/decoder/core"
	"go.uber.org/zap"

	"github.com/dreadl0ck/netcap/internal/decoder"
	decoderconfig "github.com/dreadl0ck/netcap/internal/decoder/config"
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
	// A complete request line is sufficient even when no response was captured.
	Specificity: core.SpecificityStructural,

	CanDecode: func(client, server []byte) bool {
		return containsHTTPMethod(client) || containsHTTPMethod(server) || containsHTTPProtocolName(server) || containsHTTPProtocolName(client) || (httpStart(client, false) >= 0 && httpStart(server, true) >= 0) || (httpStart(server, false) >= 0 && httpStart(client, true) >= 0)
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
)

func containsHTTPProtocolName(data []byte) bool {
	line, _, ok := bytes.Cut(data, []byte("\n"))
	line = bytes.TrimSuffix(line, []byte("\r"))
	if !ok || len(line) > 8192 {
		return false
	}
	parts := strings.SplitN(string(line), " ", 3)
	if len(parts) < 2 || (parts[0] != "HTTP/1.0" && parts[0] != "HTTP/1.1") || len(parts[1]) != 3 {
		return false
	}
	return parts[1][0] >= '1' && parts[1][0] <= '5' && parts[1][1] >= '0' && parts[1][1] <= '9' && parts[1][2] >= '0' && parts[1][2] <= '9'
}

func containsHTTPMethod(data []byte) bool {
	line, _, ok := bytes.Cut(data, []byte("\n"))
	line = bytes.TrimSuffix(line, []byte("\r"))
	if !ok || len(line) > 8192 {
		return false
	}
	parts := strings.Split(string(line), " ")
	if len(parts) != 3 || parts[1] == "" || (parts[2] != "HTTP/1.0" && parts[2] != "HTTP/1.1") {
		return false
	}
	for _, m := range httpMethods {
		if parts[0] == string(m) {
			var err error
			if parts[0] == methodCONNECT {
				_, err = http.NewRequest(parts[0], parts[1], nil)
			} else {
				_, err = url.ParseRequestURI(parts[1])
			}
			return err == nil
		}
	}
	return false
}

// A protocol preface is skipped only with a complete HTTP header on both sides.
func httpStart(data []byte, response bool) int {
	data = data[:min(len(data), 16384)]
	for i := range data {
		if i > 0 && data[i-1] != '\n' && data[i-1] != 0 {
			continue
		}
		rest := data[i:]
		valid := containsHTTPMethod(rest)
		if response {
			valid = containsHTTPProtocolName(rest)
		}
		if valid && (bytes.Contains(rest, []byte("\r\n\r\n")) || bytes.Contains(rest, []byte("\n\n"))) {
			return i
		}
	}
	return -1
}
