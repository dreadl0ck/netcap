// +build !linux

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
	"io"
	"sync/atomic"

	"github.com/dreadl0ck/gopacket/pcap"
	"github.com/pkg/errors"
)

// CollectLive starts collection of data from the given interface
// optionally a bpf can be supplied.
// this is the darwin version that uses the pcap lib with c bindings to fetch packets
// currently there is no other option to do that.
func (c *Collector) CollectLive(iface, bpf string) error {
	// open interface in live mode
	// timeout is set to 0
	// snaplen and promiscuous mode can be configured over the collector instance
	handle, err := pcap.OpenLive(iface, int32(c.config.SnapLen), c.config.Promisc, 0)
	if err != nil {
		return err
	}
	// close handle on exit
	defer handle.Close()

	// set BPF if requested
	if bpf != "" {
		err = handle.SetBPFFilter(bpf)
		if err != nil {
			return err
		}
	}

	// initialize collector
	if err = c.Init(); err != nil {
		return err
	}

	stopProgress := c.printProgressInterval()

	c.mu.Lock()
	c.isLive = true
	c.mu.Unlock()

	// read packets from channel
	for {
		// read next packet
		data, ci, err := handle.ZeroCopyReadPacketData()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}

			return errors.Wrap(err, "Error reading packet data")
		}

		// increment atomic packet counter
		atomic.AddInt64(&c.current, 1)

		// must be locked, otherwise a race occurs when sending a SIGINT
		//  and triggering wg.Wait() in another goroutine...
		c.statMutex.Lock()

		// increment wait group for packet processing
		c.wg.Add(1)

		c.statMutex.Unlock()

		c.handleRawPacketData(data, ci)
	}

	stopProgress <- struct{}{}

	// run cleanup on channel exit
	c.cleanup(false)

	return nil
}
