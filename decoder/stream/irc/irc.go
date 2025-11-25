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

package irc

import (
	"bytes"

	"github.com/dreadl0ck/netcap/decoder"
	"github.com/dreadl0ck/netcap/decoder/core"
	decoderconfig "github.com/dreadl0ck/netcap/decoder/config"
	logging "github.com/dreadl0ck/netcap/logger"
	"github.com/dreadl0ck/netcap/types"
	"go.uber.org/zap"
)

var ircLog = zap.NewNop()

// Decoder for IRC protocol analysis
var Decoder = &decoder.StreamDecoder{
	Type:        types.Type_NC_IRC,
	Name:        "IRC",
	Description: "Internet Relay Chat protocol",
	PostInit: func(sd *decoder.StreamDecoder) error {
		var err error
		ircLog, _, err = logging.InitZapLogger(
			decoderconfig.Instance.Out,
			"irc",
			decoderconfig.Instance.Debug,
		)
		if err != nil {
			return err
		}
		// Initialize DCC connection tracking
		initIRCConnectionTracker()
		return nil
	},
	CanDecode: func(client, server []byte) bool {
		// IRC typically has server responses starting with ":"
		// or client commands like NICK, USER, etc.
		if bytes.Contains(server, []byte(":")) && bytes.Contains(client, []byte("NICK")) {
			return true
		}
		// Check for common IRC server responses
		if bytes.Contains(server, []byte("001")) || bytes.Contains(server, []byte("NOTICE")) {
			return true
		}
		return false
	},
	DeInit: func(sd *decoder.StreamDecoder) error {
		return ircLog.Sync()
	},
	Factory: &ircReader{},
	Typ:     core.TCP,
}

