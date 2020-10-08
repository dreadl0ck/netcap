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
	"github.com/dreadl0ck/gopacket"
	"github.com/dreadl0ck/gopacket/pcap"

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
