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

package ssh

import (
	"bytes"

	"github.com/dreadl0ck/netcap/decoder/core"
	"go.uber.org/zap"

	"github.com/dreadl0ck/netcap/decoder"
	decoderconfig "github.com/dreadl0ck/netcap/decoder/config"
	logging "github.com/dreadl0ck/netcap/logger"
	"github.com/dreadl0ck/netcap/types"
)

var sshLog = zap.NewNop()

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// Decoder for protocol analysis and writing audit records to disk.
var Decoder = &decoder.StreamDecoder{
	Type:        types.Type_NC_SSH,
	Name:        serviceSSH,
	Description: "The Secure Shell Protocol allows controlling remote machines over an encrypted connection",
	PostInit: func(d *decoder.StreamDecoder) error {
		var err error
		sshLog, _, err = logging.InitZapLogger(
			decoderconfig.Instance.Out,
			"ssh",
			decoderconfig.Instance.Debug,
		)
		return err
	},
	CanDecode: func(client, server []byte) bool {
		result := bytes.Contains(server, sshServiceName)
		if result {
			sshLog.Info("SSH traffic detected - CanDecode matched",
				zap.Int("clientLen", len(client)),
				zap.Int("serverLen", len(server)),
				zap.String("serverPreview", string(server[:min(len(server), 100)])),
			)
		} else {
			sshLog.Debug("SSH CanDecode check failed",
				zap.Int("clientLen", len(client)),
				zap.Int("serverLen", len(server)),
			)
		}
		return result
	},
	DeInit: func(sd *decoder.StreamDecoder) error {
		return sshLog.Sync()
	},
	Factory: &sshReader{},
	Typ:     core.TCP,
}

var (
	serviceSSH     = "SSH"
	sshServiceName = []byte(serviceSSH)
)
