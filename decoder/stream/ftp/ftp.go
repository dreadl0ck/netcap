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

package ftp

import (
	"github.com/dreadl0ck/netcap/decoder"
	decoderconfig "github.com/dreadl0ck/netcap/decoder/config"
	"github.com/dreadl0ck/netcap/decoder/core"
	logging "github.com/dreadl0ck/netcap/logger"
	"github.com/dreadl0ck/netcap/types"
	"go.uber.org/zap"
)

var ftpLog = zap.NewNop()

// Decoder for FTP protocol analysis
var Decoder = &decoder.StreamDecoder{
	Type:        types.Type_NC_FTP,
	Name:        "FTP",
	Description: "File Transfer Protocol - control and data channels",
	PostInit: func(sd *decoder.StreamDecoder) error {
		var err error
		ftpLog, _, err = logging.InitZapLogger(
			decoderconfig.Instance.Out,
			"ftp",
			decoderconfig.Instance.Debug,
		)
		if err != nil {
			return err
		}
		// Initialize connection tracking
		initConnectionTracker()
		return nil
	},
	CanDecode: func(client, server []byte) bool {
		// FTP server starts with 220
		if len(server) > 3 && server[0] == '2' && server[1] == '2' && server[2] == '0' {
			return true
		}
		return false
	},
	DeInit: func(sd *decoder.StreamDecoder) error {
		return ftpLog.Sync()
	},
	Factory: &ftpReader{},
	Typ:     core.TCP,
}
