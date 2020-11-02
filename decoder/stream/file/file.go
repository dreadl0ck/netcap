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

package file

import (
	"log"
	"sync/atomic"

	"github.com/dreadl0ck/netcap/decoder"
	decoderconfig "github.com/dreadl0ck/netcap/decoder/config"
	"github.com/dreadl0ck/netcap/types"
)

// Decoder for protocol analysis and writing audit records to disk.
var Decoder = &decoder.AbstractDecoder{
	Type:        types.Type_NC_File,
	Name:        "File",
	Description: "A file that was transferred over the network",
}

// WriteFile writeDeviceProfile writes the profile.
func WriteFile(f *types.File) {
	if decoderconfig.Instance.ExportMetrics {
		f.Inc()
	}

	atomic.AddInt64(&Decoder.NumRecordsWritten, 1)

	err := Decoder.Writer.Write(f)
	if err != nil {
		log.Fatal("failed to write proto: ", err)
	}
}
