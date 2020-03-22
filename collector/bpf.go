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
	"github.com/dreadl0ck/gopacket"
	"github.com/dreadl0ck/gopacket/layers"
	"github.com/dreadl0ck/gopacket/pcap"
	"github.com/pkg/errors"
	"io"
)

// CollectBPF open the named PCAP file and sets the specified BPF filter.
func (c *Collector) CollectBPF(path string, bpf string) error {

	handle, err := pcap.OpenOffline(path)
	if err != nil {
		return err
	}
	defer handle.Close()

	if err = handle.SetBPFFilter(bpf); err != nil {
		return err
	}

	if err = c.Init(); err != nil {
		return err
	}

	// read packets
	for {

		// fetch the next packetdata and packetheader
		data, ci, err := handle.ZeroCopyReadPacketData()
		if err != nil {
			if err == io.EOF {
				break
			}
			return errors.Wrap(err, "Error reading packet data")
		}

		c.printProgress()

		p := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.Lazy)
		p.Metadata().Timestamp = ci.Timestamp
		p.Metadata().CaptureInfo = ci

		c.handlePacket(p)
	}
	c.cleanup()
	return nil
}
