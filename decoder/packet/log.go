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

package packet

import (
	"os"

	"go.uber.org/zap"
)

var (
	decoderLog *zap.Logger

	reassemblyLog *zap.Logger
	// hold a reference to the file handle so we can dump summary data tables into it.
	reassemblyLogFileHandle *os.File
)

// SetDecoderLogger sets the general decoder logger for the decoder package.
func SetDecoderLogger(lg *zap.Logger, f *os.File) {
	decoderLog = lg
}

// setReassemblyLogger sets the tcp stream reassembly logger for the decoder package.
func setReassemblyLogger(lg *zap.Logger, f *os.File) {
	reassemblyLog = lg
	reassemblyLogFileHandle = f
}
