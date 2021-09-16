// +build linux

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
	"fmt"
	"context"

	"github.com/dreadl0ck/gopacket"
	"github.com/dreadl0ck/gopacket/pcapgo"
	"github.com/pkg/errors"
)

// CollectLive starts collection of data from the given interface.
// optionally a BPF can be supplied.
// this is the linux version that uses the pure go version from pcapgo to fetch packets live.
func (c *Collector) CollectLive(i string, bpf string, ctx context.Context) error {

	// use raw socket to fetch packet on linux live mode
	handle, err := pcapgo.NewEthernetHandle(i)
	if err != nil {
		return err
	}
	defer handle.Close()

	// set BPF if requested
	if bpf != "" {
		rb, err := rawBPF(bpf)
		if err != nil {
			return err
		}
		if err := handle.SetBPF(rb); err != nil {
			return err
		}
	}

	// initialize collector
	if err := c.Init(); err != nil {
		return err
	}

	stopProgress := c.printProgressInterval()

	c.mu.Lock()
	c.isLive = true
	c.mu.Unlock()

	var (
		data []byte
		ci   gopacket.CaptureInfo
	)

	// read packets from channel
	for {
		select {
		case <-ctx.Done():
			fmt.Println("live capture canceled via context")
			goto done
		default:

			// read next packet
			data, ci, err = handle.ReadPacketData()
			if err != nil {
				if errors.Is(err, io.EOF) {
					break
				}
				return errors.Wrap(err, errReadingPacketData+" interface: "+i+" bpf: "+bpf)
			}

			// increment atomic packet counter
			atomic.AddInt64(&c.current, 1)

			// must be locked, otherwise a race occurs when sending a SIGINT
			//  and triggering wg.Wait() in another goroutine...
			c.statMutex.Lock()

			// increment wait group for packet processing
			c.wg.Add(1)

			c.statMutex.Unlock()

			c.handleRawPacketData(data, &ci)
		}
	}


done:

	// Stop progress reporting
	stopProgress <- struct{}{}

	// run cleanup on channel exit
	c.cleanup(false)

	return nil
}
