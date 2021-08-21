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
	"fmt"
	"io"
	"log"
	"os"
	"sync/atomic"
	"time"

	"github.com/dreadl0ck/gopacket"
	"github.com/dreadl0ck/gopacket/layers"
	"github.com/dreadl0ck/gopacket/pcapgo"
	"github.com/dustin/go-humanize"
	"github.com/pkg/errors"
)

const errReadingPacketData = "error reading packet data"

// OpenPCAP opens a Packet Capture file.
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

// IsPcap checks whether a file is a PCAP file.
func IsPcap(file string) (bool, error) {
	// get file handle
	f, err := os.Open(file)
	if err != nil {
		return false, err
	}

	defer func() {
		errClose := f.Close()
		if errClose != nil && !errors.Is(errClose, io.EOF) {
			fmt.Println("failed to close:", errClose)
		}
	}()

	// try to create pcap reader
	_, err = pcapgo.NewReader(f)
	if err != nil {
		// file exists but is not a pcap
		// dont return error in this case
		return false, nil
	}

	return true, nil
}

// countPackets returns the number of packets in a PCAP file.
func countPackets(path string) (count int64, err error) {
	// get reader and file handle
	r, f, err := OpenPCAP(path)
	if err != nil {
		return
	}

	defer func() {
		errClose := f.Close()
		if errClose != nil && !errors.Is(errClose, io.EOF) {
			fmt.Println(errClose)
		}
	}()

	for {
		// loop over packets and discard all data
		_, _, err = r.ZeroCopyReadPacketData()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			log.Fatal("error reading packet data: ", err)
		}

		// increment counter
		count++
	}

	return count, nil
}

// CollectPcap implements parallel decoding of incoming packets.
func (c *Collector) CollectPcap(path string) error {
	// stat input file
	stat, err := os.Stat(path)
	if err != nil {
		return errors.Wrap(err, "failed to open file")
	}

	// file exists.
	c.clearLine()
	c.printlnStdOut("opening", path+" | size:", humanize.Bytes(uint64(stat.Size())))

	// set input filesize on collector
	c.inputSize = stat.Size()

	// display total packet count
	start := time.Now()

	c.printStdOut("counting packets...")

	c.numPackets, err = countPackets(path)
	if err != nil && !(errors.Is(err, io.EOF)) {
		return err
	}

	c.clearLine()
	c.printlnStdOut("counting packets... done.", c.numPackets, "packets found in", time.Since(start))

	r, f, err := OpenPCAP(path)
	if err != nil {
		return err
	}

	defer func() {
		errClose := f.Close()
		if errClose != nil && !errors.Is(errClose, io.EOF) {
			fmt.Println(errClose)
		}
	}()

	c.handleLinkType(r.LinkType())

	// initialize collector
	if err = c.Init(); err != nil {
		return err
	}

	var (
		data         []byte
		ci           gopacket.CaptureInfo
		stopProgress = c.printProgressInterval()
	)

	for { // fetch the next packet data and packet header
		data, ci, err = r.ReadPacketData()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}

			return errors.Wrap(err, errReadingPacketData+" file: "+path)
		}

		// increment atomic packet counter
		atomic.AddInt64(&c.current, 1)

		// must be locked, otherwise a race occurs when sending a SIGINT
		//  and triggering wg.Wait() in another goroutine...
		c.statMutex.Lock()

		// increment wait group for packet processing
		c.wg.Add(1)

		c.statMutex.Unlock()

		c.handleRawPacketData(data, &ci)
	}

	// Stop progress reporting
	stopProgress <- struct{}{}

	// run cleanup on channel exit
	c.cleanup(false)

	return nil
}

func (c *Collector) handleLinkType(lt layers.LinkType) {
	c.printlnStdOut("detected link type:", lt)

	// TODO: why does this not work?
	//c.config.BaseLayer = lt.LayerType()

	switch lt {
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
	case layers.LinkTypePPP:
		c.config.BaseLayer = layers.LayerTypePPP
	case layers.LinkTypeLinuxSLL:
		c.config.BaseLayer = layers.LayerTypeLinuxSLL
	default:
		log.Fatal("unhandled link type: ", lt)
	}
}
