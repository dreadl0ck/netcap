package collector

import (
	"bytes"
	"encoding/binary"
	"io"

	"github.com/gopacket/gopacket/pcapgo"
)

// NewPCAPReader accepts classic PCAP 2.0–2.4, including gzip streams, while
// retaining the collector's allocation limits and malformed-record checks.
// The caller owns input and must close it when finished.
func NewPCAPReader(input io.Reader) (captureReader, error) {
	return newBoundedPCAPReader(input)
}

// NewCaptureReader selects by magic, not parser success. A damaged classic
// PCAP must never be retried as PCAPNG. Mixed-link PCAPNG is rejected because
// callers use LinkType to compile one BPF program or write one PCAP header.
// Collection uses openCaptureInput instead, preserving per-interface metadata.
func NewCaptureReader(input io.Reader) (captureReader, error) {
	s, err := newCaptureStream(input)
	if err != nil {
		return nil, err
	}
	var magic [4]byte
	if _, err := io.ReadFull(s.r, magic[:]); err != nil {
		return nil, err
	}
	r := io.MultiReader(bytes.NewReader(magic[:]), s.r)
	if binary.BigEndian.Uint32(magic[:]) == 0x0a0d0d0a {
		return pcapgo.NewNgReader(r, pcapgo.NgReaderOptions{ErrorOnMismatchingLinkType: true})
	}
	return NewPCAPReader(r)
}
