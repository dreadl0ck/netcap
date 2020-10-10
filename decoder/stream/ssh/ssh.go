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

package ssh

import (
	"bytes"

	"go.uber.org/zap"

	"github.com/dreadl0ck/netcap/decoder"
	decoderconfig "github.com/dreadl0ck/netcap/decoder/config"
	logging "github.com/dreadl0ck/netcap/logger"
	"github.com/dreadl0ck/netcap/types"
)

var sshLog = zap.NewNop()

var Decoder = decoder.NewStreamDecoder(
	types.Type_NC_SSH,
	serviceSSH,
	"The Secure Shell Protocol allows controlling remote machines over an encrypted connection",
	func(d *decoder.StreamDecoder) error {
		var err error
		sshLog, _, err = logging.InitZapLogger(
			decoderconfig.Instance.Out,
			"ssh",
			decoderconfig.Instance.Debug,
		)
		return err
	},
	func(client, server []byte) bool {
		return bytes.Contains(server, sshServiceName)
	},
	func(sd *decoder.StreamDecoder) error {
		return sshLog.Sync()
	},
	&sshReader{},
)

var (
	serviceSSH     = "SSH"
	sshServiceName = []byte(serviceSSH)
)
