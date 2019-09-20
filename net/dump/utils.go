package main

import (
	"flag"
	"fmt"

	"github.com/dreadl0ck/netcap"
)

func printHeader() {
	netcap.PrintLogo()
	fmt.Println()
	fmt.Println("usage examples:")
	fmt.Println("	$ net.dump -r TCP.ncap.gz")
	fmt.Println("	$ net.dump -fields -r TCP.ncap.gz")
	fmt.Println("	$ net.dump -r TCP.ncap.gz -select Timestamp,SrcPort,DstPort > tcp.csv")
	fmt.Println()
}

// usage prints the use
func printUsage() {
	printHeader()
	flag.PrintDefaults()
}
