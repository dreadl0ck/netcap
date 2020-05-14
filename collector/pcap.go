/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) 2017-2020 Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
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
	"os"
	"sync/atomic"
	"time"

	"github.com/dreadl0ck/gopacket/layers"

	"github.com/dreadl0ck/gopacket/pcapgo"
	humanize "github.com/dustin/go-humanize"
	"github.com/pkg/errors"
)

// OpenPCAP opens a Packet Capture file
func OpenPCAP(file string) (*pcapgo.Reader, *os.File, error) {
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
	r, f, err := OpenPCAP(path)
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
	c.printlnStdOut("opening", path+" | size:", humanize.Bytes(uint64(stat.Size())))

	// set input filesize on collector
	c.inputSize = stat.Size()

	// display total packet count
	start := time.Now()
	c.printStdOut("counting packets...")
	c.numPackets, err = countPackets(path)
	if err != nil {
		return err
	}

	if !c.config.Quiet {
		clearLine()
	}
	c.printlnStdOut("counting packets... done.", c.numPackets, "packets found in", time.Since(start))

	r, f, err := OpenPCAP(path)
	if err != nil {
		return err
	}
	defer f.Close()

	c.printlnStdOut("detected link type:", r.LinkType())

	switch r.LinkType() {
	case layers.LinkTypeEthernet:
		c.config.BaseLayer = layers.LayerTypeEthernet
	case layers.LinkTypeRaw:
		c.config.BaseLayer = layers.LayerTypeIPv4
	case layers.LinkTypeIPv4:
		c.config.BaseLayer = layers.LayerTypeIPv4
	case layers.LinkTypeIPv6:
		c.config.BaseLayer = layers.LayerTypeIPv6
	case layers.LinkTypeNull:
		c.config.BaseLayer = layers.LayerTypeLoopback
	case layers.LinkTypeFDDI:
		c.config.BaseLayer = layers.LayerTypeFDDI
	case layers.LinkTypeIEEE802_11:
		c.config.BaseLayer = layers.LayerTypeDot11
	case layers.LinkTypeIEEE80211Radio:
		c.config.BaseLayer = layers.LayerTypeRadioTap
	default:
		log.Fatal("unhandled link type: ", r.LinkType())
	}

	// initialize collector
	if err := c.Init(); err != nil {
		return err
	}

	stopProgress := c.printProgressInterval()

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

		// increment atomic packet counter
		atomic.AddInt64(&c.current, 1)

		// must be locked, otherwise a race occurs when sending a SIGINT
		//  and triggering wg.Wait() in another goroutine...
		c.statMutex.Lock()

		// increment wait group for packet processing
		c.wg.Add(1)

		c.statMutex.Unlock()

		c.handleRawPacketData(data, ci)
	}


	stopProgress <- struct{}{}

	c.cleanup(false)
	return nil
}
