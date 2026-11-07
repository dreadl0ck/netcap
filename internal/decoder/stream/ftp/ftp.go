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
	"github.com/dreadl0ck/netcap/internal/decoder"
	decoderconfig "github.com/dreadl0ck/netcap/internal/decoder/config"
	"github.com/dreadl0ck/netcap/internal/decoder/core"
	logging "github.com/dreadl0ck/netcap/internal/logger"
	"github.com/dreadl0ck/netcap/types"
	"go.uber.org/zap"
	"strings"
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
	// The shared 220 greeting requires FTP-specific corroboration.
	Specificity: core.SpecificityWeak,

	CanDecode: func(client, server []byte) bool {
		c, s := strings.ToUpper(string(client)), strings.ToUpper(string(server))
		if !strings.HasPrefix(s, "220 ") && !strings.HasPrefix(s, "220-") {
			return false
		}
		for _, command := range []string{"EHLO ", "HELO ", "MAIL FROM:", "AUTH PLAIN", "AUTH LOGIN", "AUTH CRAM-MD5", "AUTH XOAUTH2"} {
			if strings.HasPrefix(c, command) || strings.Contains(c, "\r\n"+command) {
				return false
			}
		}
		line, _, _ := strings.Cut(s, "\r\n")
		if strings.Contains(line, "FTP") {
			return true
		}
		for _, command := range []string{"USER ", "PASS ", "RETR ", "STOR ", "PASV\r\n", "EPSV\r\n"} {
			if strings.HasPrefix(c, command) || strings.Contains(c, "\r\n"+command) {
				return true
			}
		}
		return false
	},
	DeInit: func(sd *decoder.StreamDecoder) error {
		if err := FinalizeDataConnections(); err != nil {
			return err
		}
		return ftpLog.Sync()
	},
	Factory: &ftpReader{},
	Typ:     core.TCP,
}
