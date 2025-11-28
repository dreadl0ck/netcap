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

package smtp

import (
	"bytes"
	"strconv"

	"github.com/dreadl0ck/netcap/decoder/core"

	"go.uber.org/zap"

	"github.com/dreadl0ck/netcap/decoder"
	decoderconfig "github.com/dreadl0ck/netcap/decoder/config"
	logging "github.com/dreadl0ck/netcap/logger"
	"github.com/dreadl0ck/netcap/types"
)

var (
	smtpLog               *zap.Logger
	smtpServiceReadyBytes = []byte(strconv.Itoa(smtpServiceReady))
	smtpName              = []byte("SMTP")
)

// Decoder for protocol analysis and writing audit records to disk.
var Decoder = &decoder.StreamDecoder{
	Type:        types.Type_NC_SMTP,
	Name:        serviceSMTP,
	Description: "The Simple Mail Transfer Protocol is a communication protocol for electronic mail transmission",
	PostInit: func(d *decoder.StreamDecoder) (err error) {
		smtpLog, _, err = logging.InitZapLogger(
			decoderconfig.Instance.Out,
			"mail",
			decoderconfig.Instance.Debug,
		)

		if err != nil {
			return err
		}

		return nil
	},
	CanDecode: func(client, server []byte) bool {
		return bytes.HasPrefix(server, smtpServiceReadyBytes) && bytes.Contains(server, smtpName)
	},
	DeInit: func(sd *decoder.StreamDecoder) error {
		return smtpLog.Sync()
	},
	Factory: &smtpReader{},
	Typ:     core.TCP,
}
