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

package tacacs

import (
	"go.uber.org/zap"

	"github.com/dreadl0ck/netcap/internal/decoder"
	decoderconfig "github.com/dreadl0ck/netcap/internal/decoder/config"
	"github.com/dreadl0ck/netcap/internal/decoder/core"
	logging "github.com/dreadl0ck/netcap/internal/logger"
	"github.com/dreadl0ck/netcap/types"
)

var tacacsLog = zap.NewNop()

const serviceTACACS = "TACACS"

// Decoder for protocol analysis and writing audit records to disk.
var Decoder = &decoder.StreamDecoder{
	Type:        types.Type_NC_TACACS,
	Name:        serviceTACACS,
	Description: "TACACS+ is a protocol for remote authentication and access control via a centralized server",
	PostInit: func(d *decoder.StreamDecoder) error {
		var err error
		tacacsLog, _, err = logging.InitZapLogger(
			decoderconfig.Instance.Out,
			"tacacs",
			decoderconfig.Instance.Debug,
		)
		return err
	},
	// the whole 12-octet header: version, type, sequence and a body length that
	// has to agree with the data.
	Specificity: core.SpecificityStructural,

	CanDecode: func(client, server []byte) bool {
		return hasTACACSHeader(client) || hasTACACSHeader(server)
	},
	DeInit: func(sd *decoder.StreamDecoder) error {
		return tacacsLog.Sync()
	},
	Factory: &tacacsReader{},
	Typ:     core.TCP,
}

// TACACS+ header fields, RFC 8907 section 4.1.
const (
	tacacsMajorVersion = 0xC0

	tacacsTypeAuthentication = 0x01
	tacacsTypeAuthorization  = 0x02
	tacacsTypeAccounting     = 0x03

	// The body is encrypted and its length is the last header field; a real
	// session body is not megabytes.
	tacacsMaxBodyLen = 1 << 16
)

// hasTACACSHeader validates the whole 12-octet TACACS+ header.
//
// This used to be `data[0]&0xF0 == 0xC0` and a length floor: one nibble, which
// one binary conversation in sixteen satisfies. At port 49 that is fourth in
// the port-independent scan, and it was taking roughly that share of Modbus
// conversations, whose first byte is an arbitrary transaction id.
//
// Every field in the header is checkable, so check them.
func hasTACACSHeader(data []byte) bool {
	if len(data) < tacacsHeaderLen {
		return false
	}

	// Major version is the top nibble; the minor version is 0 or 1.
	if data[0]&0xF0 != tacacsMajorVersion || data[0]&0x0F > 1 {
		return false
	}

	switch data[1] {
	case tacacsTypeAuthentication, tacacsTypeAuthorization, tacacsTypeAccounting:
	default:
		return false
	}

	// Sequence numbers start at 1; the client sends the odd ones.
	if data[2] == 0 {
		return false
	}

	length := int(data[8])<<24 | int(data[9])<<16 | int(data[10])<<8 | int(data[11])
	if length <= 0 || length > tacacsMaxBodyLen {
		return false
	}

	// The declared body has to be present, or at least be a prefix of what is:
	// a direction may carry several packets, and a capture may be truncated
	// mid-body.
	return len(data) >= tacacsHeaderLen || length+tacacsHeaderLen >= len(data)
}
