/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package collector

import (
	"fmt"
	"io"
	"os"
	"sync/atomic"
	"time"

	"github.com/dustin/go-humanize"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/pcapgo"
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
	// Enable mixed link types to support pcapng files with multiple interface types
	// (e.g., Ethernet + FPP for IS-IS, different encapsulations)
	opts := pcapgo.DefaultNgReaderOptions
	opts.WantMixedLinkType = true
	r, err := pcapgo.NewNgReader(f, opts)
	if err != nil {
		// Close the file before returning error
		f.Close()
		// Enhance the error with file type detection
		return nil, nil, enhancePcapError(file, err)
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

			return count, errors.Wrap(err, "error reading packet data: ")
		}

		// increment counter
		count++
	}

	return
}

// CollectPcapNG implements parallel decoding of incoming packets.
func (c *Collector) CollectPcapNG(path string) error {
	// Recover from any panics during processing
	defer c.recoverFromPanic()
	ctx, finish, err := c.beginCapture()
	if err != nil {
		return err
	}
	defer c.cleanup(false)
	defer finish()

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
	c.printStdOut("counting packets...")

	start := time.Now()

	numPackets, err := countPacketsNG(path)
	if err != nil && !(errors.Is(err, io.EOF)) {
		return err
	}
	atomic.StoreInt64(&c.numPackets, numPackets)

	c.clearLine()
	c.printlnStdOut("counting packets... done.", c.numPackets, "packets found in", time.Since(start))

	r, f, err := openPcapNG(path)
	if err != nil {
		return err
	}

	defer func() {
		errClose := f.Close()
		if errClose != nil && !errors.Is(errClose, io.EOF) {
			fmt.Println(errClose)
		}
	}()

	if err = c.handleLinkType(r.LinkType()); err != nil {
		return err
	}
	defer interruptCapture(ctx, ctx, func() { _ = f.Close() })()

	// initialize collector
	if err = c.Init(); err != nil {
		return err
	}

	var (
		data         []byte
		ci           gopacket.CaptureInfo
		stopProgress = c.printProgressInterval()
	)

	for {
		// fetch the next packet data and packet header
		data, ci, err = r.ReadPacketData()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				break
			}

			return errors.Wrap(err, errReadingPacketData+" file: "+path)
		}

		if !c.handleRawPacketData(data, &ci) {
			break
		}
	}

	// Stop progress reporting
	close(stopProgress)

	return nil
}
