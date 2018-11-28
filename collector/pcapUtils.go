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
	"bufio"
	"fmt"
	"os"
	"path/filepath"

	"github.com/dreadl0ck/netcap/encoder"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

// close errors.pcap and unknown.pcap
func (c *Collector) closePcapFiles() {

	// unknown.pcap

	err := c.unkownPcapWriterBuffered.Flush()
	if err != nil {
		panic(err)
	}

	i, err := c.unknownPcapFile.Stat()
	if err != nil {
		panic(err)
	}

	// if file is empty, or a pcap with just the header
	if i.Size() == 0 || i.Size() == 24 {
		//println("removing", fd.Name())
		err := os.Remove(c.unknownPcapFile.Name())
		if err != nil {
			fmt.Println("failed to remove file:", c.unknownPcapFile.Name(), err)
		}
	}

	var (
		errSync  = c.unknownPcapFile.Sync()
		errClose = c.unknownPcapFile.Close()
	)
	if errSync != nil || errClose != nil {
		fmt.Println("error while closing", i.Name(), "errSync", errSync, "errClose", errClose)
	}

	// errors.pcap

	err = c.errorsPcapWriterBuffered.Flush()
	if err != nil {
		panic(err)
	}

	i, err = c.errorsPcapFile.Stat()
	if err != nil {
		panic(err)
	}

	// if file is empty, or a pcap with just the header
	if i.Size() == 0 || i.Size() == 24 {
		//println("removing", fd.Name())
		err := os.Remove(c.errorsPcapFile.Name())
		if err != nil {
			fmt.Println("failed to remove file:", c.errorsPcapFile.Name(), err)
		}
	}

	errSync = c.errorsPcapFile.Sync()
	errClose = c.errorsPcapFile.Close()
	if errSync != nil || errClose != nil {
		fmt.Println("error while closing", i.Name(), "errSync", errSync, "errClose", errClose)
	}
}

// create unknown.pcap file for packets with unknown layers
func (c *Collector) createUnknownPcap() {

	var err error

	// Open output pcap file and write header
	c.unknownPcapFile, err = os.Create(filepath.Join(c.config.EncoderConfig.Out, "unknown.pcap"))
	if err != nil {
		panic(err)
	}

	c.unkownPcapWriterBuffered = bufio.NewWriterSize(c.unknownPcapFile, encoder.BlockSize)
	pcapWriter := pcapgo.NewWriter(c.unkownPcapWriterBuffered)

	// set global pcap writer
	c.unkownPcapWriterAtomic = NewAtomicPcapGoWriter(pcapWriter)
	pcapWriter.WriteFileHeader(1024, layers.LinkTypeEthernet)
}

// create errors.pcap file for errors
func (c *Collector) createErrorsPcap() {

	var err error

	// Open output pcap file and write header
	c.errorsPcapFile, err = os.Create(filepath.Join(c.config.EncoderConfig.Out, "errors.pcap"))
	if err != nil {
		panic(err)
	}

	c.errorsPcapWriterBuffered = bufio.NewWriterSize(c.errorsPcapFile, encoder.BlockSize)
	pcapWriter := pcapgo.NewWriter(c.errorsPcapWriterBuffered)

	// set global pcap writer
	c.errorsPcapWriterAtomic = NewAtomicPcapGoWriter(pcapWriter)
	pcapWriter.WriteFileHeader(1024, layers.LinkTypeEthernet)
}

// write a packet to the unknown.pcap file
// if WriteUnknownPackets is set in the config
func (c *Collector) writePacketToUnknownPcap(p gopacket.Packet) {
	if c.config.WriteUnknownPackets {
		err := c.unkownPcapWriterAtomic.WritePacket(p.Metadata().CaptureInfo, p.Data())
		if err != nil {
			panic(err)
		}
	}
}

// logPacketError handles an error when decoding a packet
func (c *Collector) logPacketError(p gopacket.Packet, err string) {

	// increment errorMap stats
	c.errorMap.Inc(err)

	// write entry to errors.log
	c.errorLogFile.WriteString(p.Metadata().Timestamp.String() + "\nError: " + err + "\nPacket:\n" + p.Dump() + "\n")

	// write packet to errors.pcap
	c.writePacketToErrorsPcap(p)
}

// write a packet to the errors.pcap file
func (c *Collector) writePacketToErrorsPcap(p gopacket.Packet) {
	err := c.errorsPcapWriterAtomic.WritePacket(p.Metadata().CaptureInfo, p.Data())
	if err != nil {
		panic(err)
	}
}
