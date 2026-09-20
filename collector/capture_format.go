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
	"bufio"
	"compress/gzip"
	"encoding/binary"
	"fmt"
	"io"
	"os"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"
	"github.com/gopacket/gopacket/pcapgo"
	"github.com/pkg/errors"
)

// CaptureFormat is the container format of a capture file, determined from its
// magic number alone. It says nothing about whether the file is well formed.
type CaptureFormat int

const (
	// CaptureFormatUnknown means the magic number matched neither container.
	CaptureFormatUnknown CaptureFormat = iota
	// CaptureFormatPCAP is the classic libpcap format, any version or byte order.
	CaptureFormatPCAP
	// CaptureFormatPCAPNG is the PCAP Next Generation format.
	CaptureFormatPCAPNG
)

func (f CaptureFormat) String() string {
	switch f {
	case CaptureFormatPCAP:
		return "PCAP"
	case CaptureFormatPCAPNG:
		return "PCAPNG"
	default:
		return "unknown"
	}
}

// Magic numbers, read big-endian so the byte order the file was written in is
// visible in the value itself.
const (
	magicPCAPMicros     = 0xa1b2c3d4 // written big-endian
	magicPCAPMicrosSwap = 0xd4c3b2a1 // written little-endian
	magicPCAPNanos      = 0xa1b23c4d // written big-endian
	magicPCAPNanosSwap  = 0x4d3cb2a1 // written little-endian
	magicPCAPNG         = 0x0a0d0d0a
)

// pcapFileHeader is the 24 byte header of a classic PCAP file.
type pcapFileHeader struct {
	byteOrder    binary.ByteOrder
	nanoseconds  bool
	versionMajor uint16
	versionMinor uint16
	snapLen      uint32
	linkType     layers.LinkType
}

// supportedByPcapgo reports whether gopacket's pure Go reader accepts this
// header. pcapgo implements PCAP 2.4 only and rejects every other version,
// including the perfectly readable 2.0 and 2.1 files still found in the wild.
func (h *pcapFileHeader) supportedByPcapgo() bool {
	return h.versionMajor == 2 && h.versionMinor == 4
}

func (h *pcapFileHeader) version() string {
	return fmt.Sprintf("%d.%d", h.versionMajor, h.versionMinor)
}

// readPcapFileHeader parses the classic PCAP header from r.
func readPcapFileHeader(r io.Reader) (*pcapFileHeader, error) {
	r, err := decompressedReader(r)
	if err != nil {
		return nil, err
	}

	buf := make([]byte, 24)
	if _, err = io.ReadFull(r, buf); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return nil, errors.New("truncated PCAP file header")
		}

		return nil, err
	}

	h := &pcapFileHeader{}

	switch binary.BigEndian.Uint32(buf[:4]) {
	case magicPCAPMicros:
		h.byteOrder = binary.BigEndian
	case magicPCAPMicrosSwap:
		h.byteOrder = binary.LittleEndian
	case magicPCAPNanos:
		h.byteOrder, h.nanoseconds = binary.BigEndian, true
	case magicPCAPNanosSwap:
		h.byteOrder, h.nanoseconds = binary.LittleEndian, true
	default:
		return nil, errors.New("not a classic PCAP file header")
	}

	h.versionMajor = h.byteOrder.Uint16(buf[4:6])
	h.versionMinor = h.byteOrder.Uint16(buf[6:8])
	h.snapLen = h.byteOrder.Uint32(buf[16:20])
	h.linkType = layers.LinkType(h.byteOrder.Uint32(buf[20:24]))

	return h, nil
}

// decompressedReader mirrors pcapgo's transparent gzip handling so format
// detection and header inspection do not regress compressed PCAP support.
func decompressedReader(r io.Reader) (io.Reader, error) {
	buffered := bufio.NewReader(r)
	magic, err := buffered.Peek(2)
	if err != nil {
		return nil, err
	}

	if magic[0] != 0x1f || magic[1] != 0x8b {
		return buffered, nil
	}

	return gzip.NewReader(buffered)
}

// DetectCaptureFormat identifies the container format of a capture file from
// its magic number. A recognized format does not imply the file is valid; it
// only decides which reader is allowed to parse it.
func DetectCaptureFormat(path string) (CaptureFormat, error) {
	f, err := os.Open(path)
	if err != nil {
		return CaptureFormatUnknown, err
	}

	defer f.Close()

	reader, err := decompressedReader(f)
	if err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return CaptureFormatUnknown, nil
		}

		return CaptureFormatUnknown, err
	}

	magic := make([]byte, 4)
	if _, err = io.ReadFull(reader, magic); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			// Too short to be either container, not an I/O failure.
			return CaptureFormatUnknown, nil
		}

		return CaptureFormatUnknown, err
	}

	switch binary.BigEndian.Uint32(magic) {
	case magicPCAPMicros, magicPCAPMicrosSwap, magicPCAPNanos, magicPCAPNanosSwap:
		return CaptureFormatPCAP, nil
	case magicPCAPNG:
		return CaptureFormatPCAPNG, nil
	default:
		return CaptureFormatUnknown, nil
	}
}

// PcapReader reads packets from an opened capture file and owns the underlying
// resources, so callers only need to call Close.
type PcapReader interface {
	ReadPacketData() (data []byte, ci gopacket.CaptureInfo, err error)
	ZeroCopyReadPacketData() (data []byte, ci gopacket.CaptureInfo, err error)
	LinkType() layers.LinkType
	Close() error
}

// pcapgoReader adapts *pcapgo.Reader, which does not own the file it reads.
type pcapgoReader struct {
	*pcapgo.Reader
	f *os.File
}

func (r *pcapgoReader) Close() error {
	err := r.f.Close()
	if err != nil && !errors.Is(err, io.EOF) {
		return err
	}

	return nil
}

// libpcapReader adapts *pcap.Handle, which owns its own file handle and whose
// Close returns nothing.
type libpcapReader struct {
	*pcap.Handle
}

func (r *libpcapReader) Close() error {
	r.Handle.Close()

	return nil
}

// OpenPCAP opens a PCAP 2.4 file with pcapgo. It retains the original API for
// callers that need the concrete reader. New code should use OpenPCAPReader,
// which also accepts legacy PCAP versions through libpcap.
func OpenPCAP(path string) (*pcapgo.Reader, *os.File, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}

	r, err := pcapgo.NewReader(f)
	if err != nil {
		f.Close()

		return nil, nil, enhancePcapError(path, err)
	}

	return r, f, nil
}

// OpenPCAPReader opens a classic PCAP file for reading.
//
// PCAP 2.4 is read by the pure Go pcapgo reader. Some older-version captures
// are valid even though pcapgo refuses them on the version field alone, so
// those are handed to libpcap for validation and reading. A file that carries
// PCAP magic is never retried as PCAPNG: it stays a PCAP file and fails with a
// PCAP error.
func OpenPCAPReader(path string) (PcapReader, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}

	header, err := readPcapFileHeader(f)
	if err != nil {
		f.Close()

		return nil, enhancePcapError(path, err)
	}

	if header.supportedByPcapgo() {
		if _, err = f.Seek(0, io.SeekStart); err != nil {
			f.Close()

			return nil, err
		}

		r, errReader := pcapgo.NewReader(f)
		if errReader != nil {
			f.Close()

			return nil, enhancePcapError(path, errReader)
		}

		return &pcapgoReader{Reader: r, f: f}, nil
	}

	// Let libpcap own its own handle rather than sharing this descriptor.
	f.Close()

	handle, err := pcap.OpenOffline(path)
	if err != nil {
		return nil, errors.Wrapf(err, "PCAP version %s is not supported by the built-in reader and libpcap rejected it as well", header.version())
	}

	return &libpcapReader{Handle: handle}, nil
}

// ngReader adapts *pcapgo.NgReader, which does not own the file it reads.
type ngReader struct {
	*pcapgo.NgReader
	f *os.File
}

func (r *ngReader) Close() error {
	err := r.f.Close()
	if err != nil && !errors.Is(err, io.EOF) {
		return err
	}

	return nil
}

// OpenCapture opens a capture file of either container format, chosen by magic
// number.
//
// PCAPNG sections are read without mixed link type support so that LinkType
// reports the section's link type, which callers need in order to compile a BPF
// or write the packets back out. Collection uses its own mixed link type reader
// instead, because it resolves the link type per packet.
func OpenCapture(path string) (PcapReader, error) {
	format, err := DetectCaptureFormat(path)
	if err != nil {
		return nil, err
	}

	switch format {
	case CaptureFormatPCAP:
		return OpenPCAPReader(path)
	case CaptureFormatPCAPNG:
		f, errOpen := os.Open(path)
		if errOpen != nil {
			return nil, errOpen
		}

		r, errReader := pcapgo.NewNgReader(f, pcapgo.DefaultNgReaderOptions)
		if errReader != nil {
			f.Close()

			return nil, enhancePcapError(path, errReader)
		}

		return &ngReader{NgReader: r, f: f}, nil
	default:
		return nil, enhancePcapError(path, errors.New("unrecognized capture file magic number"))
	}
}

// CollectCapture detects the capture container and routes it to the matching
// collector. Detection and validation are deliberately separate: damaged or
// unsupported classic PCAP files remain PCAP errors instead of being retried
// and misreported as PCAPNG.
func (c *Collector) CollectCapture(path string) error {
	format, err := DetectCaptureFormat(path)
	if err != nil {
		return err
	}

	switch format {
	case CaptureFormatPCAP:
		return c.CollectPcap(path)
	case CaptureFormatPCAPNG:
		return c.CollectPcapNG(path)
	default:
		return enhancePcapError(path, errors.New("unrecognized capture file magic number"))
	}
}

// IsPcap reports whether pcapgo can open a file as classic PCAP. It retains its
// historical validation semantics for external callers. Internal routing uses
// DetectCaptureFormat so legacy and damaged PCAP files remain classified as
// PCAP even when pcapgo rejects them.
func IsPcap(file string) (bool, error) {
	f, err := os.Open(file)
	if err != nil {
		return false, err
	}
	defer f.Close()

	_, err = pcapgo.NewReader(f)
	if err != nil {
		return false, nil
	}

	return true, nil
}
