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

package imap

import (
	"bytes"

	"github.com/dreadl0ck/netcap/decoder"
	"github.com/dreadl0ck/netcap/decoder/core"
	decoderconfig "github.com/dreadl0ck/netcap/decoder/config"
	logging "github.com/dreadl0ck/netcap/logger"
	"github.com/dreadl0ck/netcap/types"
	"go.uber.org/zap"
)

var imapLog = zap.NewNop()

// IMAP server greeting patterns
var (
	imapGreeting = []byte("* OK")
	imapBye      = []byte("* BYE")
	imapStarTLS  = []byte("STARTTLS")
)

// Decoder for IMAP protocol analysis
var Decoder = &decoder.StreamDecoder{
	Type:        types.Type_NC_IMAP,
	Name:        "IMAP",
	Description: "Internet Message Access Protocol - email retrieval and management",
	PostInit: func(sd *decoder.StreamDecoder) error {
		var err error
		imapLog, _, err = logging.InitZapLogger(
			decoderconfig.Instance.Out,
			"imap",
			decoderconfig.Instance.Debug,
		)
		if err != nil {
			return err
		}
		return nil
	},
	CanDecode: func(client, server []byte) bool {
		// IMAP server starts with "* OK" greeting
		if bytes.Contains(server, imapGreeting) {
			return true
		}
		// Or client sends IMAP commands (tagged)
		if len(client) > 5 && client[0] >= 'A' && client[0] <= 'Z' {
			// Check for common IMAP commands
			if bytes.Contains(client, []byte("LOGIN")) ||
				bytes.Contains(client, []byte("SELECT")) ||
				bytes.Contains(client, []byte("CAPABILITY")) {
				return true
			}
		}
		return false
	},
	DeInit: func(sd *decoder.StreamDecoder) error {
		return imapLog.Sync()
	},
	Factory: &imapReader{},
	Typ:     core.TCP,
}

