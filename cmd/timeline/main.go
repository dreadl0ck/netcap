package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"strings"

	"github.com/dreadl0ck/netcap"
	"github.com/dreadl0ck/netcap/types"
	"github.com/gogo/protobuf/proto"
)

// Work in Progress!

// 1) Profile Creation
// What information shall be gathered about a host?
// - Geolocation based on IP
// - Application being used (via DPI or TLS fingerprinting)
// - Communicating with whom? (Server application)
// - IP addresses:
//   - Reverse DNS lookup for public addresses
//   - Which devices have been using the IP
// - Mac Addr & Lookup manufacturers
// - Flow direction:
//   - Which devices have been contacted from the user?
//   - Which devices did the user contact?

// Usage:
// $ net.capture -r traffic.pcap -include Profile

// 2) Timeline Creation
// - create a timeline per profile per day
// - use event to describe behavior on a high level

// Tool concept:
// $ net.timeline -flows Flow.ncap.gz -profiles Profile.ncap.gz

// 3) Timeline Output structure
// Generate Folder structure with timelines for each host for each day?
// profiles
// |-<MacAddr>-profile.json
// |-<MacAddr>-profile.json
// 2020-02-02
// |-<MacAddr>-timeline.csv
// |-<MacAddr>-timeline.csv
// ...

func main() {

	// parse commandline flags
	flag.Parse()

	// print version and exit
	if *flagVersion {
		fmt.Println(netcap.Version)
		os.Exit(0)
	}

	netcap.PrintBuildInfo()

	f, err := os.Open(*flagInput)
	if err != nil {
		log.Fatal(err)
	}

	// check if its an audit record file
	if !strings.HasSuffix(f.Name(), ".ncap.gz") && !strings.HasSuffix(f.Name(), ".ncap") {
		log.Fatal("input file must be an audit record file")
	}

	var (
		total = netcap.Count(*flagInput)
	)

	fmt.Println("audit records", total)

	r, err := netcap.Open(*flagInput, netcap.DefaultBufferSize)
	if err != nil {
		panic(err)
	}

	// read netcap header
	header := r.ReadHeader()
	if header.Type != types.Type_NC_UDP {
		panic("file does not contain UDP records: " + header.Type.String())
	}

	// outfile handle
	// outFile, err := os.Create(outFileName)
	// if err != nil {
	// 	panic(err)
	// }

	var (
		tcp = new(types.TCP)
		pm  proto.Message
		ok  bool
	)
	pm = tcp

	//types.Select(tcp, *flagSelect)

	if _, ok = pm.(types.AuditRecord); !ok {
		panic("type does not implement types.AuditRecord interface")
	}

	for {
		err := r.Next(tcp)
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			break
		} else if err != nil {
			panic(err)
		}

		fmt.Println(tcp.Context.SrcIP, tcp.Context.DstIP, tcp.SrcPort, tcp.DstPort)
	}
}
