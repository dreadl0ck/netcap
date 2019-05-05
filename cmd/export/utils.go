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
	"io"
	"io/ioutil"
	"log"
	"path/filepath"
	"sync"
	"time"

	"github.com/dreadl0ck/netcap/utils"

	"github.com/dreadl0ck/netcap"
	"github.com/dreadl0ck/netcap/types"
)

func printHeader() {
	netcap.PrintLogo()
	fmt.Println()
	fmt.Println("usage examples:")
	fmt.Println("	$ net.export -r dump.pcap")
	fmt.Println("	$ net.export -iface eth0 -promisc=false")
	fmt.Println("	$ net.export -r TCP.ncap.gz")
	fmt.Println("	$ net.export .")
	fmt.Println()
}

// usage prints the use
func printUsage() {
	printHeader()
	flag.PrintDefaults()
}

func exportDir(path string) {

	files, err := ioutil.ReadDir(path)
	if err != nil {
		log.Fatal("failed to read dir: ", err)
	}

	var (
		wg    sync.WaitGroup
		count = 0
	)

	for _, f := range files {

		var (
			fName = f.Name()
			ext   = filepath.Ext(fName)
		)

		if ext == ".ncap" || ext == ".gz" {

			fmt.Println("exporting", fName)
			wg.Add(1)
			count++

			go func() {
				exportFile(fName)
				wg.Done()
			}()
		}
	}

	fmt.Println("waiting for exports...")
	wg.Wait()

	fmt.Println("all exports finished!")
}

func exportFile(path string) {

	var (
		count  = 0
		r, err = netcap.Open(path)
	)
	if err != nil {
		log.Fatal("failed to open netcap file:", err)
	}
	defer r.Close()

	var (
		// read netcap file header
		header = r.ReadHeader()

		// initalize a record instance for the type from the header
		record = netcap.InitRecord(header.Type)

		previousTimestamp time.Time
	)

	for {
		// read next record
		err := r.Next(record)
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			// bail out on end of file
			break
		} else if err != nil {
			panic(err)
		}
		count++

		// assert to AuditRecord
		if p, ok := record.(types.AuditRecord); ok {

			if *flagReplay {
				t := utils.StringToTime(p.NetcapTimestamp())
				if count == 1 {
					previousTimestamp = t
				} else {
					sleep := previousTimestamp.Sub(t)
					// fmt.Println(sleep)
					time.Sleep(sleep)
					previousTimestamp = t
				}
			}

			if *flagDumpJSON {
				// dump as JSON
				j, err := p.JSON()
				if err != nil {
					log.Fatal(err)
				}
				fmt.Println(j)
			}

			// increment metric
			p.Inc()
		} else {
			log.Fatal("netcap type does not implement the types.AuditRecord interface!")
		}
	}

	fmt.Println(path, "done. processed", count, "records.")
}
