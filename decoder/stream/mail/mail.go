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

package mail

import (
	"log"
	"sync/atomic"

	"go.uber.org/zap"

	"github.com/dreadl0ck/netcap/decoder"
	decoderconfig "github.com/dreadl0ck/netcap/decoder/config"
	logging "github.com/dreadl0ck/netcap/internal/logger"
	"github.com/dreadl0ck/netcap/types"
)

var mailLog = zap.NewNop()

// Decoder for protocol analysis and writing audit records to disk.
var Decoder = &decoder.AbstractDecoder{
	Type:        types.Type_NC_Mail,
	Name:        "Mail",
	Description: "Email messages collected from the network traffic",
	PostInit: func(d *decoder.AbstractDecoder) error {
		var err error
		mailLog, _, err = logging.InitZapLogger(
			decoderconfig.Instance.Out,
			"mail",
			decoderconfig.Instance.Debug,
		)
		return err
	},
	DeInit: func(sd *decoder.AbstractDecoder) error {
		return mailLog.Sync()
	},
}

// WriteMail writes an email audit record to disk.
func WriteMail(d *types.Mail) {
	// Mail records are produced by the SMTP, POP3 and IMAP decoders, so this is
	// reached whenever mail traffic is seen even if the Mail decoder itself was
	// not selected and has no writer.
	if Decoder.Writer == nil {
		return
	}

	if decoderconfig.Instance.ExportMetrics {
		d.Inc()
	}

	atomic.AddInt64(&Decoder.NumRecordsWritten, 1)

	err := Decoder.Writer.Write(d)
	if err != nil {
		log.Println("failed to write Mail audit record:", err)
	}
}
