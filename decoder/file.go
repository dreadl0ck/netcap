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

package decoder

import (
	"log"
	"sync/atomic"

	"github.com/dreadl0ck/gopacket"
	"github.com/dreadl0ck/netcap/types"
	"github.com/gogo/protobuf/proto"
)

var (
	fileDecoderInstance *CustomDecoder
)

var fileDecoder = NewCustomDecoder(
	types.Type_NC_File,
	"File",
	"A file that was transferred over the network",
	func(d *CustomDecoder) error {
		fileDecoderInstance = d
		return nil
	},
	func(p gopacket.Packet) proto.Message {
		return nil
	},
	func(e *CustomDecoder) error {
		return nil
	},
)

// writeProfile writes the profile
func writeFile(c *types.File) {

	if fileDecoderInstance.export {
		c.Inc()
	}

	atomic.AddInt64(&fileDecoderInstance.numRecords, 1)
	err := fileDecoderInstance.writer.Write(c)
	if err != nil {
		log.Fatal("failed to write proto: ", err)
	}
}
