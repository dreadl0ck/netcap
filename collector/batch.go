/*
 * NETCAP - Traffic Analysis Framework
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
	"time"

	"github.com/dreadl0ck/netcap/encoder"
	"github.com/dreadl0ck/netcap/types"
	"github.com/dreadl0ck/gopacket"
	"github.com/dreadl0ck/gopacket/pcap"
)

// BatchInfo contains information about a Batch source.
type BatchInfo struct {
	Type types.Type
	Chan <-chan []byte
}

// InitBatching initializes batching mode and returns an array of Batchinfos and the pcap handle
// closing the handle must be done by the caller.
func (c *Collector) InitBatching(maxSize int, bpf string, in string) ([]BatchInfo, *pcap.Handle, error) {

	var chans = []BatchInfo{}

	// open live handle
	handle, err := pcap.OpenLive(in, 1024, true, 30*time.Minute)
	if err != nil {
		return chans, nil, err
	}

	// set BPF if requested
	if bpf != "" {
		err := handle.SetBPFFilter(bpf)
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

	// set live mode
	encoder.LiveMode = true

	// defer c.cleanup()

	// read packets in background routine
	go func() {
		print("decoding packets... ")
		for pack := range ps.Packets() {
			c.printProgressLive()

			// if HTTP capture is desired, tcp stream reassembly needs to be performed.
			// the gopacket/reassembly implementation does not allow packets to arrive out of order
			// therefore the http decoding must not happen in a worker thread
			// and instead be performed here to guarantee packets are being processed sequentially
			if encoder.HTTPActive {
				encoder.DecodeHTTP(pack)
			}
			c.handlePacket(pack)
		}
	}()

	// get channels for all layer encoders
	for _, encoders := range encoder.LayerEncoders {
		for _, e := range encoders {
			chans = append(chans, BatchInfo{
				Type: e.Type,
				Chan: e.GetChan(),
			})
		}
	}

	// get channels for all custom encoders
	for _, e := range encoder.CustomEncoders {
		chans = append(chans, BatchInfo{
			Type: e.Type,
			Chan: e.GetChan(),
		})
	}

	return chans, handle, nil
}
