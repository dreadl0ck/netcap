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

package irc

import (
	"bytes"

	"github.com/dreadl0ck/netcap/decoder"
	decoderconfig "github.com/dreadl0ck/netcap/decoder/config"
	"github.com/dreadl0ck/netcap/decoder/core"
	logging "github.com/dreadl0ck/netcap/logger"
	"github.com/dreadl0ck/netcap/types"
	"go.uber.org/zap"
)

var ircLog = zap.NewNop()

// Decoder for IRC protocol analysis
var Decoder = &decoder.StreamDecoder{
	Type:        types.Type_NC_IRC,
	Name:        "IRC",
	Description: "Internet Relay Chat protocol",
	PostInit: func(sd *decoder.StreamDecoder) error {
		var err error
		ircLog, _, err = logging.InitZapLogger(
			decoderconfig.Instance.Out,
			"irc",
			decoderconfig.Instance.Debug,
		)
		if err != nil {
			return err
		}
		// Initialize DCC connection tracking
		initIRCConnectionTracker()
		return nil
	},
	CanDecode: func(client, server []byte) bool {
		// IRC typically has server responses starting with ":"
		// or client commands like NICK, USER, etc.
		if bytes.Contains(server, []byte(":")) && bytes.Contains(client, []byte("NICK")) {
			return true
		}
		// Check for common IRC server responses
		if bytes.Contains(server, []byte("001")) || bytes.Contains(server, []byte("NOTICE")) {
			return true
		}
		return false
	},
	DeInit: func(sd *decoder.StreamDecoder) error {
		return ircLog.Sync()
	},
	Factory: &ircReader{},
	Typ:     core.TCP,
}
