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

	"github.com/dreadl0ck/netcap/internal/decoder/core"
	"go.uber.org/zap"

	"github.com/dreadl0ck/netcap/internal/decoder"
	decoderconfig "github.com/dreadl0ck/netcap/internal/decoder/config"
	logging "github.com/dreadl0ck/netcap/internal/logger"
	"github.com/dreadl0ck/netcap/types"
)

var sshLog = zap.NewNop()

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
	// the "SSH-" identification string at the start of a line, plus a version
	// digit after it.
	Specificity: core.SpecificityStructural,

	CanDecode: func(client, server []byte) bool {
		// Server-driven on purpose: the reader keys on the server's
		// identification string and emits a record from it, so a client
		// greeting with no server reply is not evidence of an SSH service.
		// ssh_pcap_test.go pins that.
		result := hasSSHIdentification(server)
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

var serviceSSH = "SSH"

// sshIdentPrefix opens the identification string of RFC 4253 section 4.2:
// SSH-protoversion-softwareversion.
var sshIdentPrefix = []byte("SSH-")

// hasSSHIdentification reports whether data carries an SSH identification
// string at the start of a line.
//
// This used to be Contains(server, "SSH"): three unanchored ASCII bytes
// anywhere in a whole direction, which any payload able to contain those
// letters satisfies -- an HTTP body, a file transfer, a TLS transcript. At port
// 22 it is second in the port-independent scan, so it was reached before almost
// everything.
//
// RFC 4253 section 4.2 gives the whole line a grammar:
//
//	SSH-protoversion-softwareversion SP comments CR LF
//
// Both hyphens are required, which is what separates a real identification from
// prose that happens to begin "SSH-2.0". The server may send other lines first,
// so the anchor is the line start rather than offset zero.
func hasSSHIdentification(data []byte) bool {
	for offset := 0; offset < len(data); {
		idx := bytes.Index(data[offset:], sshIdentPrefix)
		if idx < 0 {
			return false
		}

		idx += offset
		if idx == 0 || data[idx-1] == '\n' {
			if hasSSHVersionField(data[idx+len(sshIdentPrefix):]) {
				return true
			}
		}

		offset = idx + 1
	}

	return false
}

// hasSSHVersionField reports whether b opens with a protocol version followed
// by the hyphen that introduces the software version.
func hasSSHVersionField(b []byte) bool {
	i := 0
	for ; i < len(b) && (b[i] == '.' || (b[i] >= '0' && b[i] <= '9')); i++ {
	}

	// At least one version character, then the second hyphen, then something
	// for the software version to be.
	return i > 0 && i < len(b) && b[i] == '-'
}
