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

package collector

import (
	"fmt"
	"io"
	"log"
	"os"
	"time"

	"github.com/dreadl0ck/netcap/encoder"
	humanize "github.com/dustin/go-humanize"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/pkg/errors"
)

// openPcap opens pcap files.
func openPcap(file string) (*pcapgo.Reader, *os.File, error) {
	// get file handle
	f, err := os.Open(file)
	if err != nil {
		return nil, nil, err
	}

	// try to create pcap reader
	r, err := pcapgo.NewReader(f)
	if err != nil {
		return nil, nil, err
	}
	return r, f, nil
}

// IsPcap checks wheter a file is a PCAP file
func IsPcap(file string) (bool, error) {
	// get file handle
	f, err := os.Open(file)
	if err != nil {
		return false, err
	}
	defer f.Close()

	// try to create pcap reader
	_, err = pcapgo.NewReader(f)
	if err != nil {
		// file exists but is not a pcap
		// dont return error in this case
		return false, nil
	}
	return true, nil

}

// countPackets returns the number of packets in a PCAP file
func countPackets(path string) (count int64, err error) {
	// get reader and file handle
	r, f, err := openPcap(path)
	if err != nil {
		return
	}
	defer f.Close()

	for {
		// loop over packets and discard all data
		_, _, err := r.ReadPacketData()
		if err != nil {
			if err == io.EOF {
				break
			}
			log.Fatal("Error reading packet data: ", err)
		}

		// increment counter
		count++
	}

	return
}

// CollectPcap implements parallel decoding of incoming packets.
func (c *Collector) CollectPcap(path string) error {
	// stat input file
	stat, err := os.Stat(path)
	if err != nil {
		return errors.Wrap(err, "failed to open file")
	}

	// file exists.
	clearLine()
	println("opening", path+" | size:", humanize.Bytes(uint64(stat.Size())))

	// set input filesize on collector
	c.inputSize = stat.Size()

	// display total packet count
	print("counting packets...")
	start := time.Now()
	c.numPackets, err = countPackets(path)
	if err != nil {
		return err
	}
	clearLine()
	fmt.Println("counting packets... done.", c.numPackets, "packets found in", time.Since(start))

	r, f, err := openPcap(path)
	if err != nil {
		return err
	}
	defer f.Close()

	// initialize collector
	if err := c.Init(); err != nil {
		return err
	}

	print("decoding packets... ")
	for {

		// fetch the next packetdata and packetheader
		// for pcap, currently ZeroCopyReadPacketData() is not supported
		data, ci, err := r.ReadPacketData()
		if err != nil {
			if err == io.EOF {
				break
			}
			return errors.Wrap(err, "Error reading packet data: ")
		}

		// show progress
		c.printProgress()

		// create a new gopacket with lazy decoding
		// base layer is currently Ethernet
		// TODO make base layer configurable
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

		// pass packet to a worker routine
		c.handlePacket(p)
	}
	c.cleanup()
	return nil
}
