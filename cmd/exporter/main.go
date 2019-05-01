package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"

	"github.com/dreadl0ck/netcap/metrics"

	"github.com/dreadl0ck/netcap"
	"github.com/dreadl0ck/netcap/types"
)

func main() {

	flag.Parse()

	if *flagRead == "" {
		flag.PrintDefaults()
		os.Exit(1)
	}

	if filepath.Ext(*flagRead) == ".ncap" || filepath.Ext(*flagRead) == ".gz" {
		fmt.Println("opening file", *flagRead)
	} else {
		log.Fatal("expecting files with file extension .ncap or .ncap.gz")
	}

	if !*flagQuiet {
		netcap.PrintLogo()
	}

	var (
		count  = 0
		r, err = netcap.Open(*flagRead)
	)
	if err != nil {
		log.Fatal("failed to open netcap file:", err)
	}
	defer r.Close()

	fmt.Println("reading file header")

	var (
		// read netcap file header
		header = r.ReadHeader()

		// initalize a record instance for the type from the header
		record = netcap.InitRecord(header.Type)
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

	fmt.Println("done. processed", count, "records.")

	fmt.Println("serving metrics at", *flagAddress)
	metrics.ServeMetricsAt(*flagAddress)

	<-make(chan bool)
}
