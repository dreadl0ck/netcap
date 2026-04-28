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

package kerberosaudit

import (
	"go.uber.org/zap"

	"github.com/dreadl0ck/netcap/decoder"
	decoderconfig "github.com/dreadl0ck/netcap/decoder/config"
	"github.com/dreadl0ck/netcap/decoder/core"
	logging "github.com/dreadl0ck/netcap/internal/logger"
	"github.com/dreadl0ck/netcap/types"
)

var kerberosLog = zap.NewNop()

const serviceKerberos = "Kerberos"

// Decoder for protocol analysis and writing audit records to disk.
var Decoder = &decoder.StreamDecoder{
	Type:        types.Type_NC_Kerberos,
	Name:        serviceKerberos,
	Description: "Kerberos is a network authentication protocol using tickets for secure identity verification",
	PostInit: func(d *decoder.StreamDecoder) error {
		var err error
		kerberosLog, _, err = logging.InitZapLogger(
			decoderconfig.Instance.Out,
			"kerberos",
			decoderconfig.Instance.Debug,
		)
		return err
	},
	CanDecode: func(client, server []byte) bool {
		return hasKerberosTag(client) || hasKerberosTag(server)
	},
	DeInit: func(sd *decoder.StreamDecoder) error {
		return kerberosLog.Sync()
	},
	Factory: &kerberosReader{},
	Typ:     core.All, // Kerberos uses both TCP and UDP
}

// hasKerberosTag checks for Kerberos ASN.1 application tags.
// TCP Kerberos has a 4-byte record mark (length) prefix before the ASN.1 data.
func hasKerberosTag(data []byte) bool {
	if len(data) < 2 {
		return false
	}

	// Check directly for ASN.1 application tags (UDP case)
	if isKerberosAppTag(data[0]) {
		return true
	}

	// Check after 4-byte TCP record mark prefix
	if len(data) >= 5 && isKerberosAppTag(data[4]) {
		return true
	}

	return false
}

// isKerberosAppTag returns true if the byte is a known Kerberos ASN.1 application tag.
func isKerberosAppTag(b byte) bool {
	switch b {
	case 0x6a, // tag 10 = AS-REQ
		0x6b, // tag 11 = AS-REP
		0x6c, // tag 12 = TGS-REQ
		0x6d, // tag 13 = TGS-REP
		0x7e: // tag 30 = KRB-ERROR
		return true
	}
	return false
}
