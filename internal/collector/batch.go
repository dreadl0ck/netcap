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

// InitBatching initializes batching mode and returns decoder channels and the
// pcap handle. Closing the handle stops capture early; lifecycle cleanup also
// closes it when capture ends.
func (c *Collector) InitBatching(bpf string, in string) ([]BatchInfo, *pcap.Handle, error) {
	var chans []BatchInfo //nolint:prealloc
	ctx, finish, err := c.beginCapture()
	if err != nil {
		return nil, nil, err
	}
	started := false
	defer func() {
		if !started {
			finish()
			c.cleanup(false)
		}
	}()

	// open live handle
	handle, err := pcap.OpenLive(in, int32(c.config.SnapLen), c.config.Promisc, c.liveReadTimeout())
	if err != nil {
		return chans, nil, err
	}
	defer func() {
		if !started {
			handle.Close()
		}
	}()

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
	// Batching is a channel sink even when callers pass ordinary capture defaults.
	decoderConfig := c.config.DecoderConfig.Clone()
	decoderConfig.Chan = true
	decoderConfig.Buffer, decoderConfig.Compression = false, false
	if decoderConfig.ChanSize <= 0 {
		decoderConfig.ChanSize = 1024
	}
	decoderConfig.CSV, decoderConfig.JSON, decoderConfig.Null, decoderConfig.Elastic = false, false, false, false
	c.config.DecoderConfig = decoderConfig
	err = c.Init()
	if err != nil {
		return chans, nil, err
	}

	chans = c.batchChannels()

	started = true
	go func() {
		defer c.cleanup(false)
		defer finish()
		defer handle.Close()
		defer interruptCapture(ctx, ctx, handle.Close)()
		for ctx.Err() == nil {
			p, err := ps.NextPacket()
			if err == pcap.NextErrorTimeoutExpired {
				continue
			}
			if err != nil || !c.handlePacket(p) {
				return
			}
			c.printProgressLive()
		}
	}()
	return chans, handle, nil
}

// batchChannels collects the record channel of every initialized decoder.
// Every channel must be drained: an undrained one blocks its decoder once full.
// Decoders sharing a writer (one stream decoder on several ports) share a
// channel, which is returned once.
func (c *Collector) batchChannels() []BatchInfo {
	var (
		chans []BatchInfo
		seen  = make(map[<-chan []byte]bool)
	)
	add := func(t types.Type, ch <-chan []byte) {
		if ch == nil || seen[ch] {
			return
		}
		seen[ch] = true
		chans = append(chans, BatchInfo{Type: t, Chan: ch})
	}

	for _, decoders := range c.goPacketDecoders {
		for _, e := range decoders {
			add(e.Type, e.GetChan())
		}
	}
	for _, d := range c.packetDecoders {
		add(d.GetType(), d.GetChan())
	}
	for _, d := range c.streamDecoders {
		add(d.GetType(), d.GetChan())
	}
	for _, d := range c.abstractDecoders {
		add(d.GetType(), d.GetChan())
	}

	return chans
}
