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
	"os"
	"sync/atomic"
	"time"

	"github.com/dreadl0ck/gopacket/pcapgo"
	"github.com/dustin/go-humanize"
	"github.com/pkg/errors"
)

// openPcap opens pcap files.
func openPcapNG(file string) (*pcapgo.NgReader, *os.File, error) {
	// get file handle
	f, err := os.Open(file)
	if err != nil {
		return nil, nil, err
	}

	// try to create pcap reader
	r, err := pcapgo.NewNgReader(f, pcapgo.DefaultNgReaderOptions)
	if err != nil {
		return nil, nil, err
	}

	return r, f, nil
}

// countPackets returns the number of packets in a PCAP file.
func countPacketsNG(path string) (count int64, err error) {
	// get reader and file handle
	r, f, err := openPcapNG(path)
	if err != nil {
		return
	}
	defer f.Close()

	for {
		// loop over packets and discard all data
		_, _, err := r.ZeroCopyReadPacketData()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return count, errors.Wrap(err, "Error reading packet data: ")
		}

		// increment counter
		count++
	}

	return
}

// CollectPcapNG implements parallel decoding of incoming packets.
func (c *Collector) CollectPcapNG(path string) error {
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
	c.printStdOut("counting packets...")
	start := time.Now()
	c.numPackets, err = countPacketsNG(path)
	if err != nil {
		return err
	}
	clearLine()
	c.printlnStdOut("counting packets... done.", c.numPackets, "packets found in", time.Since(start))

	r, f, err := openPcapNG(path)
	if err != nil {
		return err
	}
	defer f.Close()

	// initialize collector
	if err := c.Init(); err != nil {
		return err
	}

	stopProgress := c.printProgressInterval()

	for {
		// fetch the next packetdata and packetheader
		data, ci, err := r.ReadPacketData()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return errors.Wrap(err, "Error reading packet data")
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
