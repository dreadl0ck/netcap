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

package smb

import (
	"bytes"

	"github.com/dreadl0ck/netcap/decoder"
	decoderconfig "github.com/dreadl0ck/netcap/decoder/config"
	"github.com/dreadl0ck/netcap/decoder/core"
	logging "github.com/dreadl0ck/netcap/internal/logger"
	"github.com/dreadl0ck/netcap/types"
	"go.uber.org/zap"
)

var smbLog = zap.NewNop()

// SMB protocol constants
const (
	// SMB1 header signature
	SMB1Signature = "\xFFSMB"
	// SMB2/3 header signature
	SMB2Signature = "\xFESMB"
)

// Decoder for SMB protocol analysis
var Decoder = &decoder.StreamDecoder{
	Type:        types.Type_NC_SMB,
	Name:        "SMB",
	Description: "Server Message Block protocol - Windows file sharing",
	PostInit: func(sd *decoder.StreamDecoder) error {
		var err error
		smbLog, _, err = logging.InitZapLogger(
			decoderconfig.Instance.Out,
			"smb",
			decoderconfig.Instance.Debug,
		)
		if err != nil {
			return err
		}
		// Start file handle cleanup
		startSMBCleanup()
		return nil
	},
	CanDecode: func(client, server []byte) bool {
		// Check for SMB1 or SMB2/3 signature
		return bytes.Contains(server, []byte(SMB1Signature)) ||
			bytes.Contains(server, []byte(SMB2Signature)) ||
			bytes.Contains(client, []byte(SMB1Signature)) ||
			bytes.Contains(client, []byte(SMB2Signature))
	},
	DeInit: func(sd *decoder.StreamDecoder) error {
		return smbLog.Sync()
	},
	Factory: &smbReader{},
	Typ:     core.TCP,
}
