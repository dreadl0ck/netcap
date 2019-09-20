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

package capture

var (
	flagInterface     string
	flagBPF           string
	flagInclude       string
	flagExclude       string
	flagInput         string
	flagOutDir        string
	flagBaseLayer     string
	flagDecodeOptions string

	flagEncoders              bool
	flagPromiscMode           bool
	flagPayload               bool
	flagPrintProtocolOverview bool
	flagCompress              bool
	flagBuffer                bool
	flagCPUProfile            bool
	flagMemProfile            bool
	flagIngoreUnknown         bool
	flagVersion               bool

	flagWorkers      int
	flagPacketBuffer int
	flagSnapLen      int
)
