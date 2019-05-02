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

package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/dreadl0ck/netcap/metrics"

	"github.com/dreadl0ck/netcap"
)

func main() {

	flag.Parse()

	if !*flagQuiet {
		netcap.PrintLogo()
	}

	if *flagRead != "" {

		stat, err := os.Stat(*flagRead)
		if err != nil {
			log.Fatal("failed to stat input:", err)
		}

		if stat.IsDir() {
			exportDir(*flagRead)
		} else {
			if filepath.Ext(*flagRead) == ".ncap" || filepath.Ext(*flagRead) == ".gz" {
				fmt.Println("opening file", *flagRead)
			} else {
				log.Fatal("expecting files with file extension .ncap or .ncap.gz")
			}
			exportFile(*flagRead)
		}
	} else {
		exportDir(".")
	}

	fmt.Println("serving metrics at", *flagAddress)
	metrics.ServeMetricsAt(*flagAddress)

	<-make(chan bool)
}
