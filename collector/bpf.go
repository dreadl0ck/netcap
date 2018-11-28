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

// CollectBPF open the named PCAP file and sets the specified BPF filter
func (c *Collector) CollectBPF(path string, bpf string) {

	handle, err := pcap.OpenOffline(path)
	if err != nil {
		panic(err)
	}
	defer handle.Close()

	err = handle.SetBPFFilter(bpf)
	if err != nil {
		panic(err)
	}

	c.Init()

	// read packets
	print("decoding packets... ")
	for {

		// fetch the next packetdata and packetheader
		data, ci, err := handle.ZeroCopyReadPacketData()
		if err != nil {
			if err == io.EOF {
				break
			}
			log.Fatal("Error reading packet data: ", err)
		}

		c.printProgress()

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
		c.handlePacket(p)
	}
	c.cleanup()
}
