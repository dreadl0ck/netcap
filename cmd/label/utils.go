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
	fmt.Println("	$ net.label -r traffic.pcap")
	fmt.Println("	$ net.label -r traffic.pcap -out output_dir")
	fmt.Println("	$ net.label -r taffic.pcap -progress")
	fmt.Println("	$ net.label -r taffic.pcap -collect")
	fmt.Println()
}

// usage prints the use
func printUsage() {
	printHeader()
	flag.PrintDefaults()
}
