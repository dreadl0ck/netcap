// +build linux

package collector

import (
	"io"
	"log"

	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"

	"github.com/dreadl0ck/netcap/encoder"
	"github.com/google/gopacket"
)

// CollectLive starts collection of data from the given interface
// optionally a BPF can be supplied
// this is the linux version that uses the pure go version from pcapgo to fetch packets live
func (c *Collector) CollectLive(i string, bpf string) {

	// use raw socket to fetch packet on linux live mode
	handle, err := pcapgo.NewEthernetHandle(i)
	if err != nil {
		panic(err)
	}
	defer handle.Close()

	// set BPF if requested
	if bpf != "" {
		err := handle.SetBPFFilter(bpf)
		if err != nil {
			panic(err)
		}
	}

	// initialize collector
	c.Init()

	encoder.LiveMode = true
	print("decoding packets... ")

	// read packets from channel
	for {

		// read next packet
		data, ci, err := handle.ZeroCopyReadPacketData()
		if err != nil {
			if err == io.EOF {
				break
			}
			log.Fatal("Error reading packet data: ", err)
		}

		c.printProgressLive()

		// init packet and set capture info and timestamp
		p := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.Lazy)
		p.Metadata().Timestamp = ci.Timestamp
		p.Metadata().CaptureInfo = ci

		// if HTTP capture is desired, tcp stream reassembly needs to be performed.
		// the gopacket/reassembly implementation does not allow packets to arrive out of order
		// therefore the http decoding must not happen in a worker thread
		// and instead be performed here to guarantee packets are being processed sequentially
		if encoder.HTTPActive {
			encoder.DecodeHTTP(pack)
		}

		// pass packet to worker for decoding and further processing
		c.handlePacket(pack)
	}

	// run cleanup on channel exit
	c.cleanup()
}
