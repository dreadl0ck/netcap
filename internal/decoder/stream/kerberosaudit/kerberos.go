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

	"github.com/dreadl0ck/netcap/internal/decoder"
	decoderconfig "github.com/dreadl0ck/netcap/internal/decoder/config"
	"github.com/dreadl0ck/netcap/internal/decoder/core"
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
//
// The tag alone is one byte out of five accepted values, so testing it at two
// offsets across both directions gave four chances at 5/256 to claim any binary
// conversation -- and this decoder is sixth in the fallback scan, ahead of most
// of the estate. It took roughly one Modbus and one CIP conversation in fifty,
// and any DNP3 conversation whose outstation address low byte happened to be
// 106-109 or 126, because data[4] is that address.
//
// The tag is therefore only believed when the length that follows it agrees
// with the data present. That is what a DER header gives you for free.
func hasKerberosTag(data []byte) bool {
	if len(data) < 2 {
		return false
	}

	// UDP, or TCP once the record mark has been consumed: the tag is first.
	if isKerberosAppTag(data[0]) && derMessageFits(data, len(data)) {
		return true
	}

	// TCP: a 4-byte big-endian record mark precedes the ASN.1 message. Check it
	// before trusting the byte at offset 4, or the record mark's own bytes are
	// read as a tag.
	if len(data) >= 6 && isKerberosAppTag(data[4]) {
		mark := int(data[0])<<24 | int(data[1])<<16 | int(data[2])<<8 | int(data[3])
		// A stream may carry several messages, so the mark bounds the first one
		// rather than matching the whole direction.
		if mark >= minKerberosMessage && mark <= len(data)-4 && derMessageFits(data[4:], mark) {
			return true
		}
	}

	return false
}

// minKerberosMessage is a floor on a complete message. The smallest real
// KRB-ERROR runs to several dozen octets; without a floor, three bytes whose
// declared length happens to match are accepted as Kerberos.
const minKerberosMessage = 32

// derMessageFits reports whether b opens an application-tagged DER message that
// accounts for avail bytes.
//
// "Accounts for" rather than "fits within" is the point. A one-octet body fits
// inside any buffer, which is how a Modbus transaction id whose high byte
// happened to be 0x6a was read as an AS-REQ. The message must consume the
// available bytes exactly, or leave a remainder that itself opens another
// Kerberos message, which is what a stream carrying several of them looks like.
func derMessageFits(b []byte, avail int) bool {
	if avail < minKerberosMessage || len(b) < avail {
		return false
	}

	size, ok := derMessageSize(b[:avail])
	if !ok || size > avail {
		return false
	}

	if size == avail {
		return true
	}

	return isKerberosAppTag(b[size]) && derMessageFits(b[size:], avail-size)
}

// derMessageSize returns the total octets of the tag-length-value at the start
// of b.
//
// Only the definite forms are accepted: Kerberos is DER, which forbids the
// indefinite form, so 0x80 here means this is not Kerberos.
func derMessageSize(b []byte) (int, bool) {
	if len(b) < 2 {
		return 0, false
	}

	first := b[1]
	if first < 0x80 {
		// Short form: the length is the octet itself. Bound it against the data
		// present, or the size returned indexes past the end.
		if int(first) == 0 || 2+int(first) > len(b) {
			return 0, false
		}

		return 2 + int(first), true
	}

	n := int(first & 0x7F)
	if n == 0 || n > 4 || len(b) < 2+n {
		return 0, false
	}

	length := 0
	for _, v := range b[2 : 2+n] {
		length = length<<8 | int(v)
	}

	if length <= 0 || 2+n+length > len(b) {
		return 0, false
	}

	return 2 + n + length, true
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
