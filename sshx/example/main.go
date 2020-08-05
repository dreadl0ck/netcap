package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/dreadl0ck/gopacket"
	"github.com/dreadl0ck/gopacket/layers"
	"github.com/dreadl0ck/gopacket/pcap"

	"github.com/dreadl0ck/netcap/sshx"
)

func main() {

	var (
		flagInterface = flag.String("iface", "en0", "Network interface to capture on")
		flagPcap      = flag.String("pcap", "", "use pcap file")
		flagBPF       = flag.String("bpf", "tcp", "bpf filter")
	)

	flag.Parse()

	// redirect to stdout (log pkg logs to stderr by default)
	// to allow grepping the result through a simple pipe
	log.SetOutput(os.Stdout)

	var (
		handle *pcap.Handle
		err    error
	)

	if *flagPcap != "" {
		fmt.Println("Opening file", *flagPcap)
		handle, err = pcap.OpenOffline(*flagPcap)
	} else {
		fmt.Println("Listening on", *flagInterface)

		// snapLen = 1514 (1500 Ethernet MTU + 14 byte Ethernet Header)
		handle, err = pcap.OpenLive(*flagInterface, 1514, false, pcap.BlockForever)
	}
	if err != nil {
		log.Fatal(err)
	}

	// set bpf
	err = handle.SetBPFFilter(*flagBPF)
	if err != nil {
		log.Fatal(err)
	}

	// create packet source
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	// handle packets
	for packet := range packetSource.Packets() {
		// process TLS client hello
		clientHello := sshx.GetClientHello(packet)
		if clientHello != nil {
			destination := "[" + packet.NetworkLayer().NetworkFlow().Dst().String() + ":" + packet.TransportLayer().TransportFlow().Dst().String() + "]"
			if tcp, ok := packet.TransportLayer().(*layers.TCP); ok {
				log.Printf("%s Client hello from port %s to %s", destination, tcp.SrcPort, tcp.DstPort)
			}
		}
	}
}
