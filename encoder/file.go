/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) 2017 Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

package encoder

import (
	"github.com/dreadl0ck/gopacket"
	"github.com/dreadl0ck/netcap/types"
	"github.com/golang/protobuf/proto"
	"log"
	"sync/atomic"
)

var (
	fileEncoderInstance *CustomEncoder
)

var fileEncoder = CreateCustomEncoder(types.Type_NC_File, "File", func(d *CustomEncoder) error {
	fileEncoderInstance = d
	return nil
}, func(p gopacket.Packet) proto.Message {
	return nil
}, func(e *CustomEncoder) error {
	return nil
})

// writeProfile writes the profile
func writeFile(c *types.File) {

	if fileEncoderInstance.export {
		c.Inc()
	}

	atomic.AddInt64(&fileEncoderInstance.numRecords, 1)
	err := fileEncoderInstance.writer.Write(c)
	if err != nil {
		log.Fatal("failed to write proto: ", err)
	}
}
