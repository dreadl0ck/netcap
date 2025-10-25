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
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
	"github.com/pkg/errors"

	"github.com/dreadl0ck/netcap/defaults"
)

// fileTypeInfo represents information about a file format based on its magic number
type fileTypeInfo struct {
	name        string
	description string
	suggestion  string
}

// knownMagicNumbers maps magic numbers to file format information
var knownMagicNumbers = map[uint32]fileTypeInfo{
	// PCAP formats
	0xa1b2c3d4: {
		name:        "PCAP",
		description: "Standard PCAP file (little-endian)",
		suggestion:  "This appears to be a valid PCAP file. Try using CollectPcap() instead.",
	},
	0xd4c3b2a1: {
		name:        "PCAP",
		description: "Standard PCAP file (big-endian)",
		suggestion:  "This appears to be a valid PCAP file. Try using CollectPcap() instead.",
	},
	0xa1b23c4d: {
		name:        "PCAP",
		description: "Modified PCAP file with nanosecond resolution (little-endian)",
		suggestion:  "This is a PCAP file with nanosecond timestamps.",
	},
	0x4d3cb2a1: {
		name:        "PCAP",
		description: "Modified PCAP file with nanosecond resolution (big-endian)",
		suggestion:  "This is a PCAP file with nanosecond timestamps.",
	},
	0x0a0d0d0a: {
		name:        "PCAPNG",
		description: "PCAP Next Generation format",
		suggestion:  "This appears to be a valid PCAPNG file.",
	},

	// Archive formats
	0x504b0304: {
		name:        "ZIP",
		description: "ZIP archive",
		suggestion:  "This is a ZIP archive. Extract the PCAP/PCAPNG file first before processing.",
	},
	0x1f8b0800: {
		name:        "GZIP",
		description: "GZIP compressed file",
		suggestion:  "This is a GZIP compressed file. Decompress it first: gunzip <file>",
	},
	0x425a6839: {
		name:        "BZIP2",
		description: "BZIP2 compressed file",
		suggestion:  "This is a BZIP2 compressed file. Decompress it first: bunzip2 <file>",
	},
	0x1f9e0800: {
		name:        "GZIP (old)",
		description: "GZIP compressed file (old format)",
		suggestion:  "This is a GZIP compressed file. Decompress it first: gunzip <file>",
	},

	// Other capture formats
	0x58435032: {
		name:        "Snoop",
		description: "Snoop capture file (Sun/Solaris)",
		suggestion:  "This is a Snoop capture file. Convert it to PCAP format first using editcap or tcpdump.",
	},
	0x7663722d: {
		name:        "NetMon",
		description: "Microsoft Network Monitor capture",
		suggestion:  "This is a NetMon capture file. Convert it to PCAP format first using editcap.",
	},

	// Text/Data formats
	0x7b226e61: {
		name:        "JSON",
		description: "JSON text file",
		suggestion:  "This appears to be a JSON file, not a packet capture.",
	},
	0x3c3f786d: {
		name:        "XML",
		description: "XML text file",
		suggestion:  "This appears to be an XML file, not a packet capture.",
	},
}

// identifyFileTypeByMagic reads the first 4 bytes of a file and identifies its type
func identifyFileTypeByMagic(filePath string) (uint32, *fileTypeInfo, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return 0, nil, err
	}
	defer f.Close()

	// Read first 4 bytes (magic number)
	magic := make([]byte, 4)
	n, err := io.ReadFull(f, magic)
	if err != nil {
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			return 0, nil, fmt.Errorf("file is too small (only %d bytes) to be a valid packet capture", n)
		}
		return 0, nil, err
	}

	// Convert to uint32 (little-endian first)
	magicLE := binary.LittleEndian.Uint32(magic)

	// Check if we know this magic number
	if info, ok := knownMagicNumbers[magicLE]; ok {
		return magicLE, &info, nil
	}

	// Try big-endian interpretation
	magicBE := binary.BigEndian.Uint32(magic)
	if info, ok := knownMagicNumbers[magicBE]; ok {
		return magicBE, &info, nil
	}

	return magicLE, nil, nil
}

// invokeFileCommand runs the system 'file' command on the given file path
// Returns the output string and any error. Returns empty string if file command not available.
func invokeFileCommand(filePath string) string {
	// Check if file command exists
	_, err := exec.LookPath("file")
	if err != nil {
		// file command not available
		return ""
	}

	// Run file command
	cmd := exec.Command("file", "-b", filePath)
	output, err := cmd.Output()
	if err != nil {
		// Command failed, return empty
		return ""
	}

	// Clean up output (remove trailing newline/whitespace)
	result := strings.TrimSpace(string(output))

	return result
}

// enhancePcapError wraps PCAP/PCAPNG opening errors with helpful information
func enhancePcapError(filePath string, originalErr error) error {
	if originalErr == nil {
		return nil
	}

	// Try to identify the file type
	magic, fileInfo, err := identifyFileTypeByMagic(filePath)
	if err != nil {
		// Could not read magic number
		return errors.Wrap(originalErr, fmt.Sprintf("cannot read file '%s'", filePath))
	}

	// Build enhanced error message
	var enhancedMsg string

	if fileInfo != nil {
		// We identified the file type
		enhancedMsg = fmt.Sprintf(
			"File format error: %s\n"+
				"  File: %s\n"+
				"  Detected format: %s - %s (magic: 0x%08x)\n"+
				"  Suggestion: %s\n"+
				"  Original error: %v",
			fileInfo.name,
			filePath,
			fileInfo.name,
			fileInfo.description,
			magic,
			fileInfo.suggestion,
			originalErr,
		)
	} else {
		// Unknown file type
		// Try to interpret magic as ASCII for additional context
		magicBytes := make([]byte, 4)
		binary.LittleEndian.PutUint32(magicBytes, magic)
		asciiHint := ""

		// Check if bytes are printable ASCII
		allPrintable := true
		for _, b := range magicBytes {
			if b < 32 || b > 126 {
				allPrintable = false
				break
			}
		}
		if allPrintable {
			asciiHint = fmt.Sprintf(" (ASCII: '%s')", string(magicBytes))
		}

		// Invoke system 'file' command for additional context
		fileOutput := invokeFileCommand(filePath)
		fileCommandInfo := ""
		if fileOutput != "" {
			fileCommandInfo = fmt.Sprintf("  System 'file' command identifies this as: %s\n  \n", fileOutput)
		}

		enhancedMsg = fmt.Sprintf(
			"File format error: Unknown or unsupported format\n"+
				"  File: %s\n"+
				"  Magic number: 0x%08x%s\n"+
				"  %s"+
				"  This does not appear to be a valid PCAP or PCAPNG file.\n"+
				"  \n"+
				"  Possible causes:\n"+
				"  - File is corrupted or incomplete\n"+
				"  - File is in an unsupported capture format\n"+
				"  - File is compressed (try: gunzip, bunzip2, or unzip)\n"+
				"  - File is not actually a packet capture\n"+
				"  \n"+
				"  Original error: %v",
			filePath,
			magic,
			asciiHint,
			fileCommandInfo,
			originalErr,
		)
	}

	return errors.New(enhancedMsg)
}

// close errors.pcap and unknown.pcap.
func (c *Collector) closePcapFiles() error {
	// unknown.pcap

	if c.unkownPcapWriterBuffered != nil {
		err := c.unkownPcapWriterBuffered.Flush()
		if err != nil {
			return err
		}
		c.unkownPcapWriterBuffered = nil
	}

	if c.unknownPcapFile != nil {
		i, err := c.unknownPcapFile.Stat()
		if err != nil {
			return err
		}

		fileName := c.unknownPcapFile.Name()

		if err = c.unknownPcapFile.Sync(); err != nil {
			return err
		}

		if err = c.unknownPcapFile.Close(); err != nil {
			return err
		}

		// Nil out the file handle to prevent double-close
		c.unknownPcapFile = nil

		// if file is empty, or a pcap with just the header
		if i.Size() == 0 || i.Size() == 24 {
			// println("removing", fd.Name())
			err = os.Remove(fileName)
			if err != nil {
				return errors.Wrap(err, "failed to remove file: "+fileName)
			}
		}
	}

	// errors.pcap

	if c.errorsPcapWriterBuffered != nil {
		if err := c.errorsPcapWriterBuffered.Flush(); err != nil {
			return err
		}
		c.errorsPcapWriterBuffered = nil
	}

	if c.errorsPcapFile != nil {

		info, err := c.errorsPcapFile.Stat()
		if err != nil {
			return err
		}

		fileName := c.errorsPcapFile.Name()

		if err = c.errorsPcapFile.Sync(); err != nil {
			return err
		}

		if err = c.errorsPcapFile.Close(); err != nil {
			return err
		}

		// Nil out the file handle to prevent double-close
		c.errorsPcapFile = nil

		// if file is empty, or a pcap with just the header
		if info.Size() == 0 || info.Size() == 24 {
			// println("removing", fd.Name())

			if err = os.Remove(fileName); err != nil {
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

	// write entry to errors.log (check if file is still open)
	c.mu.Lock()
	if c.errorLogFile != nil {
		_, _ = c.errorLogFile.WriteString(p.Metadata().Timestamp.String() + "\nError: " + err + "\nPacket:\n" + p.Dump() + "\n")
	}
	c.mu.Unlock()

	// write packet to errors.pcap
	return c.writePacketToErrorsPcap(p)
}

// writePacketToErrorsPcap writes a packet to the errors.pcap file.
func (c *Collector) writePacketToErrorsPcap(p gopacket.Packet) error {
	return c.errorsPcapWriterAtomic.writePacket(p.Metadata().CaptureInfo, p.Data())
}
