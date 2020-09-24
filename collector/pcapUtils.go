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
	"bufio"
	"os"
	"path/filepath"

	"github.com/dreadl0ck/gopacket"
	"github.com/dreadl0ck/gopacket/layers"
	"github.com/dreadl0ck/gopacket/pcapgo"
	"github.com/pkg/errors"

	"github.com/dreadl0ck/netcap/defaults"
)

// close errors.pcap and unknown.pcap.
func (c *Collector) closePcapFiles() error {
	// unknown.pcap

	if c.unkownPcapWriterBuffered != nil {
		err := c.unkownPcapWriterBuffered.Flush()
		if err != nil {
			return err
		}
	}

	if c.unknownPcapFile != nil {
		i, err := c.unknownPcapFile.Stat()
		if err != nil {
			return err
		}

		if err = c.unknownPcapFile.Sync(); err != nil {
			return err
		}

		if err = c.unknownPcapFile.Close(); err != nil {
			return err
		}

		// if file is empty, or a pcap with just the header
		if i.Size() == 0 || i.Size() == 24 {
			// println("removing", fd.Name())
			err = os.Remove(c.unknownPcapFile.Name())
			if err != nil {
				return errors.Wrap(err, "failed to remove file: "+c.unknownPcapFile.Name())
			}
		}
	}

	// errors.pcap

	if c.errorsPcapWriterBuffered != nil {
		if err := c.errorsPcapWriterBuffered.Flush(); err != nil {
			return err
		}
	}

	if c.errorsPcapFile != nil {

		info, err := c.errorsPcapFile.Stat()
		if err != nil {
			return err
		}

		if err = c.errorsPcapFile.Sync(); err != nil {
			return err
		}

		if err = c.errorsPcapFile.Close(); err != nil {
			return err
		}

		// if file is empty, or a pcap with just the header
		if info.Size() == 0 || info.Size() == 24 {
			// println("removing", fd.Name())

			if err = os.Remove(c.errorsPcapFile.Name()); err != nil {
				return err
			}
		}
	}

	return nil
}

// create unknown.pcap file for packets with unknown layers.
func (c *Collector) createUnknownPcap() error {
	var err error

	// Open output pcap file and write header
	c.unknownPcapFile, err = os.Create(filepath.Join(c.config.DecoderConfig.Out, "unknown.pcap"))
	if err != nil {
		return err
	}

	c.unkownPcapWriterBuffered = bufio.NewWriterSize(c.unknownPcapFile, defaults.BufferSize)
	pcapWriter := pcapgo.NewWriter(c.unkownPcapWriterBuffered)

	// set global pcap writer
	c.unkownPcapWriterAtomic = newAtomicPcapGoWriter(pcapWriter)

	if err = pcapWriter.WriteFileHeader(1024, layers.LinkTypeEthernet); err != nil {
		return err
	}

	return nil
}

// create errors.pcap file for errors.
func (c *Collector) createErrorsPcap() error {
	var err error

	// Open output pcap file and write header
	c.errorsPcapFile, err = os.Create(filepath.Join(c.config.DecoderConfig.Out, "errors.pcap"))
	if err != nil {
		return err
	}

	c.errorsPcapWriterBuffered = bufio.NewWriterSize(c.errorsPcapFile, defaults.BufferSize)
	pcapWriter := pcapgo.NewWriter(c.errorsPcapWriterBuffered)

	// set global pcap writer
	c.errorsPcapWriterAtomic = newAtomicPcapGoWriter(pcapWriter)

	if err = pcapWriter.WriteFileHeader(1024, layers.LinkTypeEthernet); err != nil {
		return err
	}

	return nil
}

// writePacketToUnknownPcap writes a packet to the unknown.pcap file
// if WriteUnknownPackets is set in the config.
func (c *Collector) writePacketToUnknownPcap(p gopacket.Packet) error {
	if c.config.WriteUnknownPackets {
		return c.unkownPcapWriterAtomic.writePacket(p.Metadata().CaptureInfo, p.Data())
	}

	return nil
}

// logPacketError handles an error when decoding a packet.
func (c *Collector) logPacketError(p gopacket.Packet, err string) error {
	// increment errorMap stats
	c.errorMap.Inc(err)

	if !c.config.LogErrors {
		return nil
	}

	// write entry to errors.log
	_, _ = c.errorLogFile.WriteString(p.Metadata().Timestamp.String() + "\nError: " + err + "\nPacket:\n" + p.Dump() + "\n")

	// write packet to errors.pcap
	return c.writePacketToErrorsPcap(p)
}

// writePacketToErrorsPcap writes a packet to the errors.pcap file.
func (c *Collector) writePacketToErrorsPcap(p gopacket.Packet) error {
	return c.errorsPcapWriterAtomic.writePacket(p.Metadata().CaptureInfo, p.Data())
}
