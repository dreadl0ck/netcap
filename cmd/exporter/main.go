package main

import (
	"fmt"
	"io"
	"log"
	"os"

	"github.com/dreadl0ck/netcap/metrics"

	"github.com/dreadl0ck/netcap"
	"github.com/dreadl0ck/netcap/types"
)

func main() {
	var (
		count  = 0
		r, err = netcap.Open(os.Args[1])
	)
	if err != nil {
		panic(err)
	}
	defer r.Close()

	var (
		header = r.ReadHeader()
		record = netcap.InitRecord(header.Type)
	)

	for {
		err := r.Next(record)
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			break
		} else if err != nil {
			panic(err)
		}
		count++

		if p, ok := record.(types.AuditRecord); ok {
			j, err := p.JSON()
			if err != nil {
				log.Fatal(err)
			}
			fmt.Println(j)
			p.Inc()
		} else {
			log.Fatal("netcap type does not implement the types.AuditRecord interface!")
		}
	}

	fmt.Println("done")

	metrics.ServeMetricsAt("127.0.0.1:7777")

	<-make(chan bool)
}
