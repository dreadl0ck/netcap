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

package stream

import (
	"bytes"
	"github.com/dreadl0ck/netcap/types"
	"strconv"
)

var smtpDecoder = NewStreamDecoder(
	types.Type_NC_SMTP,
	serviceSMTP,
	"The Simple Mail Transfer Protocol is a communication protocol for electronic mail transmission",
	nil,
	func(client, server []byte) bool {
		return bytes.HasPrefix(server, smtpServiceReadyBytes) && bytes.Contains(server, smtpName)
	},
	nil,
	&smtpReader{},
)

var (
	smtpServiceReadyBytes = []byte(strconv.Itoa(smtpServiceReady))
	smtpName              = []byte("SMTP")
)
