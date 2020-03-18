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
	"io"
	"os"
	"time"

	"github.com/dreadl0ck/gopacket/pcapgo"
	humanize "github.com/dustin/go-humanize"
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

// countPackets returns the number of packets in a PCAP file
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
			if err == io.EOF {
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
	c.printStdOut("opening", path+" | size:", humanize.Bytes(uint64(stat.Size())))

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
	c.printStdOut("counting packets... done.", c.numPackets, "packets found in", time.Since(start))

	r, f, err := openPcapNG(path)
	if err != nil {
		return err
	}
	defer f.Close()

	// initialize collector
	if err := c.Init(); err != nil {
		return err
	}

	c.printStdOut("decoding packets... ")
	for {
		// fetch the next packetdata and packetheader
		// for pcapNG this uses ZeroCopyReadPacketData()
		data, ci, err := r.ZeroCopyReadPacketData()
		if err != nil {
			if err == io.EOF {
				break
			}
			return errors.Wrap(err, "Error reading packet data")
		}

		c.handleRawPacketData(data, ci)
	}
	c.cleanup()
	return nil
}
