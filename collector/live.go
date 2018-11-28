// +build darwin

/*
 * NETCAP - Network Capture Toolkit
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

package collector

import (
	"io"
	"log"

	"github.com/dreadl0ck/netcap/encoder"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// CollectLive starts collection of data from the given interface
// optionally a bpf can be supplied
// this is the darwin version that uses the pcap lib with c bindings to fetch packets
// currently there is no other option to do that
func (c *Collector) CollectLive(i string, bpf string) {

	// open interface in live mode
	// timeout is set to 0
	// snaplen and promiscous mode can be configured over the collector instance
	handle, err := pcap.OpenLive(i, int32(c.config.SnapLen), c.config.Promisc, 0)
	if err != nil {
		panic(err)
	}
	// close handle on exit
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
			encoder.DecodeHTTP(p)
		}

		// pass packet to worker for decoding and further processing
		c.handlePacket(p)
	}

	// run cleanup on channel exit
	c.cleanup()
}
