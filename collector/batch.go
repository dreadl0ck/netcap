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
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/pcap"

	"github.com/dreadl0ck/netcap/types"
)

// BatchInfo contains information about a Batch source.
type BatchInfo struct {
	Type types.Type
	Chan <-chan []byte
}

// InitBatching initializes batching mode and returns an array of Batchinfos and the pcap handle
// closing the handle must be done by the caller.
func (c *Collector) InitBatching(bpf string, in string) ([]BatchInfo, *pcap.Handle, error) {
	var chans []BatchInfo //nolint:prealloc

	// open live handle
	handle, err := pcap.OpenLive(in, int32(c.config.SnapLen), c.config.Promisc, c.config.Timeout)
	if err != nil {
		return chans, nil, err
	}

	// set BPF if requested
	if bpf != "" {
		err = handle.SetBPFFilter(bpf)
		if err != nil {
			return chans, nil, err
		}
	}

	// init packet source
	ps := gopacket.NewPacketSource(handle, handle.LinkType())

	// init collector
	err = c.Init()
	if err != nil {
		return chans, nil, err
	}

	// read packets in background routine
	go func() {
		for p := range ps.Packets() {
			c.printProgressLive()

			// TODO: avoid duplicate alloc
			c.handlePacket(p)
		}
	}()

	// get channels for all gopacket decoders
	for _, decoders := range c.goPacketDecoders {
		for _, e := range decoders {
			chans = append(chans, BatchInfo{
				Type: e.Type,
				Chan: e.GetChan(),
			})
		}
	}

	// get channels for all custom decoders
	for _, d := range c.packetDecoders {
		chans = append(chans, BatchInfo{
			Type: d.GetType(),
			Chan: d.GetChan(),
		})
	}

	return chans, handle, nil
}
