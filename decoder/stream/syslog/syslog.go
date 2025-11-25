/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) 2017-2020 Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

package syslog

import (
	"go.uber.org/zap"

	"github.com/dreadl0ck/netcap/decoder"
	"github.com/dreadl0ck/netcap/decoder/core"
	decoderconfig "github.com/dreadl0ck/netcap/decoder/config"
	logging "github.com/dreadl0ck/netcap/logger"
	"github.com/dreadl0ck/netcap/types"
)

var syslogLog = zap.NewNop()

const serviceSyslog = "Syslog"

// Decoder for protocol analysis and writing audit records to disk.
var Decoder = &decoder.StreamDecoder{
	Type:        types.Type_NC_Syslog,
	Name:        serviceSyslog,
	Description: "Syslog is a standard for message logging, used for security event monitoring",
	PostInit: func(d *decoder.StreamDecoder) error {
		var err error
		syslogLog, _, err = logging.InitZapLogger(
			decoderconfig.Instance.Out,
			"syslog",
			decoderconfig.Instance.Debug,
		)
		return err
	},
	CanDecode: func(client, server []byte) bool {
		// Syslog messages start with <PRI> where PRI is 1-3 digits
		// Check for '<' followed by digits and '>'
		if len(server) > 3 && server[0] == '<' {
			for i := 1; i < len(server) && i < 5; i++ {
				if server[i] == '>' {
					return true
				}
				if server[i] < '0' || server[i] > '9' {
					break
				}
			}
		}
		if len(client) > 3 && client[0] == '<' {
			for i := 1; i < len(client) && i < 5; i++ {
				if client[i] == '>' {
					return true
				}
				if client[i] < '0' || client[i] > '9' {
					break
				}
			}
		}
		return false
	},
	DeInit: func(sd *decoder.StreamDecoder) error {
		return syslogLog.Sync()
	},
	Factory: &syslogReader{},
	Typ:     core.UDP, // Syslog primarily uses UDP (port 514)
}

