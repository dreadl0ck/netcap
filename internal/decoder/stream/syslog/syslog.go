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

package syslog

import (
	"go.uber.org/zap"

	"github.com/dreadl0ck/netcap/internal/decoder"
	decoderconfig "github.com/dreadl0ck/netcap/internal/decoder/config"
	"github.com/dreadl0ck/netcap/internal/decoder/core"
	logging "github.com/dreadl0ck/netcap/internal/logger"
	"github.com/dreadl0ck/netcap/types"
)

var syslogLog = zap.NewNop()

const serviceSyslog = "Syslog"

// Decoder for protocol analysis and writing audit records to disk.
var Decoder = &decoder.StreamDecoder{
	Type:        types.Type_NC_Syslog,
	Name:        serviceSyslog,
	Description: "Syslog is a standard for message logging, used for security event monitoring",
	PostInit: func(d *decoder.StreamDecoder) error {
		var err error
		syslogLog, _, err = logging.InitZapLogger(
			decoderconfig.Instance.Out,
			"syslog",
			decoderconfig.Instance.Debug,
		)
		return err
	},
	// one fixed byte and a digit run.
	Specificity: core.SpecificityWeak,

	CanDecode: func(client, server []byte) bool {
		return hasSyslogPrefix(client) || hasSyslogPrefix(server)
	},
	DeInit: func(sd *decoder.StreamDecoder) error {
		return syslogLog.Sync()
	},
	Factory: &syslogReader{},
	Typ:     core.All,
}
