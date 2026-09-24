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

	"github.com/dreadl0ck/netcap/internal/decoder"
	decoderconfig "github.com/dreadl0ck/netcap/internal/decoder/config"
	"github.com/dreadl0ck/netcap/internal/decoder/core"
	logging "github.com/dreadl0ck/netcap/internal/logger"
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
		// Server replies, matched on their form rather than as bare substrings.
		//
		// This was Contains(server, "001") || Contains(server, "NOTICE") with no
		// companion condition and no length guard, so three ASCII bytes
		// occurring anywhere in a binary server direction claimed the
		// conversation -- and at port 6667 that shadowed every decoder above it.
		//
		// RFC 1459 gives both a shape: a reply is a colon-prefixed prefix, then
		// the command surrounded by spaces.
		return hasIRCReply(server, []byte(" 001 ")) || hasIRCReply(server, []byte(" NOTICE "))
	},
	DeInit: func(sd *decoder.StreamDecoder) error {
		return ircLog.Sync()
	},
	Factory: &ircReader{},
	Typ:     core.TCP,
}

// hasIRCReply reports whether a line carrying command appears in data, where
// the line begins with the ':' of an IRC prefix.
//
// Matching the line start is what stops an arbitrary occurrence of the bytes
// counting: a reply is ":<prefix> <command> <params>", so the command is
// preceded by a prefix on the same line.
func hasIRCReply(data, command []byte) bool {
	for offset := 0; ; {
		idx := bytes.Index(data[offset:], command)
		if idx < 0 {
			return false
		}

		idx += offset

		// Walk back to the start of the line and require an IRC prefix there.
		start := bytes.LastIndexByte(data[:idx], '\n') + 1
		if data[start] == ':' && idx > start {
			return true
		}

		offset = idx + 1
		if offset >= len(data) {
			return false
		}
	}
}
