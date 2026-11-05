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

	"github.com/dreadl0ck/netcap/internal/decoder/core"

	"go.uber.org/zap"

	"github.com/dreadl0ck/netcap/internal/decoder"
	decoderconfig "github.com/dreadl0ck/netcap/internal/decoder/config"
	logging "github.com/dreadl0ck/netcap/internal/logger"
	"github.com/dreadl0ck/netcap/types"
)

var (
	smtpLog  *zap.Logger
	smtpName = []byte("SMTP")
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
	// SMTP-specific greetings or client commands outrank a shared numeric reply.
	Specificity: core.SpecificityStructural,

	CanDecode: func(client, server []byte) bool {
		s, c := bytes.ToUpper(server), bytes.ToUpper(client)
		if replyPrefix(s) && bytes.Contains(s, smtpName) {
			return true
		}
		for _, prefix := range [][]byte{[]byte("EHLO "), []byte("HELO "), []byte("MAIL FROM:")} {
			if bytes.HasPrefix(c, prefix) {
				return true
			}
		}
		return false
	},
	DeInit: func(sd *decoder.StreamDecoder) error {
		return smtpLog.Sync()
	},
	Factory: &smtpReader{},
	Typ:     core.TCP,
}

func replyPrefix(b []byte) bool {
	return len(b) >= 4 && b[0] >= '2' && b[0] <= '5' && b[1] >= '0' && b[1] <= '9' && b[2] >= '0' && b[2] <= '9' && (b[3] == ' ' || b[3] == '-')
}

// PartialGreeting is weak evidence and requires a known SMTP service port.
func PartialGreeting(client, server []byte) bool {
	if !replyPrefix(server) {
		return false
	}
	c := bytes.ToUpper(client)
	if len(c) == 0 {
		return true
	}
	for _, command := range []string{"EHLO ", "HELO ", "AUTH ", "MAIL FROM:", "RCPT TO:", "QUIT\r\n", "RSET\r\n", "NOOP\r\n", "STARTTLS\r\n"} {
		if bytes.HasPrefix(c, []byte(command)) {
			return true
		}
	}
	return false
}
