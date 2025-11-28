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

package imap

import (
	"bytes"

	"github.com/dreadl0ck/netcap/decoder"
	decoderconfig "github.com/dreadl0ck/netcap/decoder/config"
	"github.com/dreadl0ck/netcap/decoder/core"
	logging "github.com/dreadl0ck/netcap/logger"
	"github.com/dreadl0ck/netcap/types"
	"go.uber.org/zap"
)

var imapLog = zap.NewNop()

// IMAP server greeting patterns
var (
	imapGreeting = []byte("* OK")
	imapBye      = []byte("* BYE")
	imapStarTLS  = []byte("STARTTLS")
)

// Decoder for IMAP protocol analysis
var Decoder = &decoder.StreamDecoder{
	Type:        types.Type_NC_IMAP,
	Name:        "IMAP",
	Description: "Internet Message Access Protocol - email retrieval and management",
	PostInit: func(sd *decoder.StreamDecoder) error {
		var err error
		imapLog, _, err = logging.InitZapLogger(
			decoderconfig.Instance.Out,
			"imap",
			decoderconfig.Instance.Debug,
		)
		if err != nil {
			return err
		}
		return nil
	},
	CanDecode: func(client, server []byte) bool {
		// IMAP server starts with "* OK" greeting
		if bytes.Contains(server, imapGreeting) {
			return true
		}
		// Or client sends IMAP commands (tagged)
		if len(client) > 5 && client[0] >= 'A' && client[0] <= 'Z' {
			// Check for common IMAP commands
			if bytes.Contains(client, []byte("LOGIN")) ||
				bytes.Contains(client, []byte("SELECT")) ||
				bytes.Contains(client, []byte("CAPABILITY")) {
				return true
			}
		}
		return false
	},
	DeInit: func(sd *decoder.StreamDecoder) error {
		return imapLog.Sync()
	},
	Factory: &imapReader{},
	Typ:     core.TCP,
}
