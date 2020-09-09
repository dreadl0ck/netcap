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

package capture

import (
	"fmt"

	"github.com/klauspost/pgzip"

	"github.com/dreadl0ck/netcap/io"
)

func printHeader() {
	io.PrintLogo()
	fmt.Println()
	fmt.Println("capture tool usage examples:")
	fmt.Println("	$ net capture -read dump.pcap")
	fmt.Println("	$ net capture -iface eth0")
	fmt.Println()
}

// usage prints the use.
func printUsage() {
	printHeader()
	fs.PrintDefaults()
}

const (
	pgzipMaxSpeed       = "max-speed"
	pgzipMaxCompression = "max-compression"
	pgzipNone           = "none"
)

func getCompressionLevel(in string) int {
	switch in {
	case pgzipMaxSpeed:
		return pgzip.BestSpeed
	case pgzipMaxCompression:
		return pgzip.BestCompression
	case pgzipNone:
		return pgzip.NoCompression
	default:
		return pgzip.DefaultCompression
	}
}

func compressionLevelToString(in int) string {
	switch in {
	case pgzip.BestSpeed:
		return pgzipMaxSpeed
	case pgzip.BestCompression:
		return pgzipMaxCompression
	case pgzip.NoCompression:
		return pgzipNone
	default:
		return "default"
	}
}
