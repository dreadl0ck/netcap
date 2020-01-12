// +build linux

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
	"io"

	"github.com/dreadl0ck/netcap/encoder"
	"github.com/dreadl0ck/gopacket/pcapgo"
	"github.com/pkg/errors"
)

// CollectLive starts collection of data from the given interface.
// optionally a BPF can be supplied.
// this is the linux version that uses the pure go version from pcapgo to fetch packets live.
func (c *Collector) CollectLive(i string, bpf string) error {
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

	encoder.LiveMode = true

	// read packets from channel
	for {

		// read next packet
		data, ci, err := handle.ReadPacketData()
		if err != nil {
			if err == io.EOF {
				break
			}
			return errors.Wrap(err, "Error reading packet data")
		}

		c.handleRawPacketData(data, ci)
	}

	// run cleanup on channel exit
	c.cleanup()
	return nil
}
