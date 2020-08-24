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

package label

import (
	"fmt"

	"github.com/dreadl0ck/netcap/io"
)

func printHeader() {
	io.PrintLogo()
	fmt.Println()
	fmt.Println("label tool usage examples:")
	fmt.Println("	$ net label -read traffic.pcap")
	fmt.Println("	$ net label -read traffic.pcap -out output_dir")
	fmt.Println("	$ net label -read taffic.pcap -progress")
	fmt.Println("	$ net label -read taffic.pcap -collect")
	fmt.Println()
}

// usage prints the use.
func printUsage() {
	printHeader()
	fs.PrintDefaults()
}
