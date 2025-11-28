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

package pop3

import (
	"bytes"

	"github.com/dreadl0ck/netcap/decoder/core"
	"go.uber.org/zap"

	"github.com/dreadl0ck/netcap/decoder"
	decoderconfig "github.com/dreadl0ck/netcap/decoder/config"
	logging "github.com/dreadl0ck/netcap/logger"
	"github.com/dreadl0ck/netcap/types"
)

// Decoder for protocol analysis and writing audit records to disk.
var Decoder = &decoder.StreamDecoder{
	Type:        types.Type_NC_POP3,
	Name:        servicePOP3,
	Description: "The POP3 protocol is used to fetch emails from a mail server",
	PostInit: func(sd *decoder.StreamDecoder) (err error) {
		pop3Log, _, err = logging.InitZapLogger(
			decoderconfig.Instance.Out,
			"pop3",
			decoderconfig.Instance.Debug,
		)
		if err != nil {
			return err
		}
		return nil
	},
	CanDecode: func(client, server []byte) bool {
		return bytes.Contains(server, pop3Ident)
	},
	DeInit: func(sd *decoder.StreamDecoder) error {
		return pop3Log.Sync()
	},
	Factory: &pop3Reader{},
	Typ:     core.TCP,
}

var (
	pop3Ident   = []byte("POP server ready")
	servicePOP3 = "POP3"
	pop3Log     *zap.Logger
)
