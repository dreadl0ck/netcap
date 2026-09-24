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

package socks

import (
	"go.uber.org/zap"

	"github.com/dreadl0ck/netcap/internal/decoder"
	decoderconfig "github.com/dreadl0ck/netcap/internal/decoder/config"
	"github.com/dreadl0ck/netcap/internal/decoder/core"
	logging "github.com/dreadl0ck/netcap/internal/logger"
	"github.com/dreadl0ck/netcap/types"
)

var socksLog = zap.NewNop()

const serviceSOCKS = "SOCKS"

// maxSocks5Methods bounds the authentication method count in a greeting.
// RFC 1928 allows up to 255, but only four are assigned and real clients offer
// one to four; a generous ceiling still excludes any binary payload whose
// second byte happens to be large.
const maxSocks5Methods = 16

// Decoder for protocol analysis and writing audit records to disk.
var Decoder = &decoder.StreamDecoder{
	Type:        types.Type_NC_SOCKS,
	Name:        serviceSOCKS,
	Description: "SOCKS is a proxy protocol for routing packets between client and server through a proxy",
	PostInit: func(d *decoder.StreamDecoder) error {
		var err error
		socksLog, _, err = logging.InitZapLogger(
			decoderconfig.Instance.Out,
			"socks",
			decoderconfig.Instance.Debug,
		)
		return err
	},
	// Varies with the data: a greeting the server answered with a method
	// selection is corroborated, a client-side greeting alone is three bytes.
	Specificity: core.SpecificityWeak,
	Confidence:  socksConfidence,
	CanDecode: func(client, server []byte) bool {
		// SOCKS5 greeting: version 0x05, a method count, then that many method
		// bytes.
		//
		// The count used to be compared against the length of the entire
		// concatenated direction, which makes the test easier the longer the
		// stream gets rather than harder. Every DNP3 conversation of 102 bytes
		// or more satisfied it: DNP3 frames begin 0x05 0x64, so the version
		// byte matched and 0x64 was read as "100 authentication methods".
		//
		// No client offers 100 methods -- the registry has four assigned values
		// -- so bounding the count is what separates the two protocols.
		if len(client) >= 3 && client[0] == 0x05 {
			methods := int(client[1])
			if methods >= 1 && methods <= maxSocks5Methods && len(client) >= 2+methods {
				return true
			}
		}
		// SOCKS4 request starts with version byte (0x04) and command byte
		if len(client) >= 9 && client[0] == 0x04 && (client[1] == 0x01 || client[1] == 0x02) {
			return true
		}

		return false
	},
	DeInit: func(sd *decoder.StreamDecoder) error {
		return socksLog.Sync()
	},
	Factory: &socksReader{},
	Typ:     core.TCP, // SOCKS uses TCP port 1080
}

// socksConfidence reports whether the server corroborated a SOCKS5 greeting.
//
// A greeting alone is one fixed byte and a bounded count, which a DCE/RPC
// header also satisfies -- version 5, minor 0 or 1, packet type under 20 -- and
// dcerpc sits at port 135 against socks at 1080. A server that replied with a
// method selection settles it.
func socksConfidence(client, server []byte) int {
	if len(server) >= 2 && server[0] == 0x05 && isSocks5Method(server[1]) {
		return core.SpecificityStructural
	}

	return core.SpecificityWeak
}

// isSocks5Method reports whether b is a method a server would select: no
// authentication, GSSAPI, username/password, or "none acceptable".
func isSocks5Method(b byte) bool {
	switch b {
	case 0x00, 0x01, 0x02, 0xFF:
		return true
	}

	return false
}
