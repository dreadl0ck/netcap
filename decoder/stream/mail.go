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
	"log"
	"sync/atomic"

	"github.com/dreadl0ck/netcap/types"
)

var mailDecoderInstance *Decoder

var mailDecoder = NewStreamDecoder(
	types.Type_NC_Mail,
	"Mail",
	"Email messages collected from the network traffic",
	func(d *Decoder) error {
		mailDecoderInstance = d

		return nil
	},
	nil,
	nil,
	nil,
)

// writeMail writes the profile.
func writeMail(d *types.Mail) {
	if conf.ExportMetrics {
		d.Inc()
	}

	atomic.AddInt64(&mailDecoderInstance.numRecords, 1)

	err := mailDecoderInstance.writer.Write(d)
	if err != nil {
		log.Fatal("failed to write proto: ", err)
	}
}
