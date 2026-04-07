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

package zabbix

import (
	"bytes"

	"go.uber.org/zap"

	"github.com/dreadl0ck/netcap/decoder"
	decoderconfig "github.com/dreadl0ck/netcap/decoder/config"
	"github.com/dreadl0ck/netcap/decoder/core"
	logging "github.com/dreadl0ck/netcap/internal/logger"
	"github.com/dreadl0ck/netcap/types"
)

var zabbixLog = zap.NewNop()

const serviceZabbix = "Zabbix"

// zabbixMagic is the 5-byte magic header for the Zabbix protocol.
var zabbixMagic = []byte("ZBXD\x01")

// Decoder for protocol analysis and writing audit records to disk.
var Decoder = &decoder.StreamDecoder{
	Type:        types.Type_NC_Zabbix,
	Name:        serviceZabbix,
	Description: "Zabbix is a network monitoring protocol for collecting metrics and monitoring infrastructure health",
	PostInit: func(d *decoder.StreamDecoder) error {
		var err error
		zabbixLog, _, err = logging.InitZapLogger(
			decoderconfig.Instance.Out,
			"zabbix",
			decoderconfig.Instance.Debug,
		)
		return err
	},
	CanDecode: func(client, server []byte) bool {
		if len(client) >= 5 && bytes.Equal(client[:5], zabbixMagic) {
			return true
		}
		if len(server) >= 5 && bytes.Equal(server[:5], zabbixMagic) {
			return true
		}
		return false
	},
	DeInit: func(sd *decoder.StreamDecoder) error {
		return zabbixLog.Sync()
	},
	Factory: &zabbixReader{},
	Typ:     core.TCP,
}
