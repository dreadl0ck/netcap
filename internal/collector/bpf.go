/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 */

package collector

import (
	"fmt"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"
)

// CollectBPF reads a capture through the same bounded reader, input report
// and evidence manifest as CollectPcap/CollectPcapNG, admitting only the
// packets the BPF filter matches. It used libpcap's reader, which wrote no
// capture-input.json and stopped at the first damaged record.
func (c *Collector) CollectBPF(path, bpf string) error {
	isPcap, err := IsPcap(path)
	if err != nil {
		return err
	}
	c.bpfFilter = bpf
	defer func() { c.bpfFilter = "" }()
	return c.collectCaptureInput(path, !isPcap)
}

const bpfSnaplen = 262144

// captureBPF compiles the filter once per link type; PCAPNG interfaces can differ.
type captureBPF struct {
	expr     string
	programs map[layers.LinkType]*pcap.BPF
}

func newCaptureBPF(expr string, link layers.LinkType) (*captureBPF, error) {
	f := &captureBPF{expr: expr, programs: map[layers.LinkType]*pcap.BPF{}}
	if _, err := f.program(link); err != nil {
		return nil, err
	}
	return f, nil
}

func (f *captureBPF) program(link layers.LinkType) (*pcap.BPF, error) {
	if program, ok := f.programs[link]; ok {
		return program, nil
	}
	program, err := pcap.NewBPF(link, bpfSnaplen, f.expr)
	if err != nil {
		return nil, fmt.Errorf("compile BPF %q for link type %d: %w", f.expr, link, err)
	}
	f.programs[link] = program
	return program, nil
}

func (f *captureBPF) matches(link layers.LinkType, ci gopacket.CaptureInfo, data []byte) (bool, error) {
	program, err := f.program(link)
	if err != nil {
		return false, err
	}
	return program.Matches(ci, data), nil
}
