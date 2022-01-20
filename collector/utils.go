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
	"fmt"
	"os"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/dreadl0ck/gopacket"
	"github.com/dreadl0ck/gopacket/layers"
	"github.com/dreadl0ck/gopacket/pcap"
	"github.com/gogo/protobuf/proto"
	"golang.org/x/net/bpf"
)

func (c *Collector) handleRawPacketData(data []byte, ci *gopacket.CaptureInfo) {
	// when not using lazy here, the packet will be decoded on the main thread!
	p := gopacket.NewPacket(data, c.config.BaseLayer, c.config.DecodeOptions)
	p.Metadata().CaptureInfo = *ci

	// pass packet to a worker routine
	c.handlePacket(p)
}

// printProgressLive prints live statistics.
func (c *Collector) printProgressLive() {
	atomic.AddInt64(&c.current, 1)

	// must be locked, otherwise a race occurs when sending a SIGINT and triggering wg.Wait() in another goroutine...
	c.statMutex.Lock()

	c.wg.Add(1)

	// dont print message when collector is about to shutdown
	if c.shutdown {
		c.statMutex.Unlock()

		return
	}
	c.statMutex.Unlock()

	if c.current%1000 == 0 {
		c.clearLine()
		if !c.config.DecoderConfig.Quiet {
			fmt.Print("running since ", time.Since(c.start), ", captured ", c.current, " packets...")
		}
	}
}

// dumpProto prints a protobuf Message.
//goland:noinspection GoUnusedFunction
func dumpProto(pb proto.Message) {
	println(proto.MarshalTextString(pb))
}

func (c *Collector) clearLine() {
	if !c.config.DecoderConfig.Quiet {
		print("\033[2K\r")
	}
}

func share(current, total int64) string {
	percent := (float64(current) / float64(total)) * 100
	var pad string
	switch {
	case percent < 10.00:
		pad = "  "
	case percent < 100.00:
		pad = " "
	}

	return pad + strconv.FormatFloat(percent, 'f', 3, 64) + "%"
}

func rawBPF(filter string) ([]bpf.RawInstruction, error) {
	// use pcap bpf compiler to get raw bpf instruction
	pcapBPF, err := pcap.CompileBPFFilter(layers.LinkTypeEthernet, 65535, filter)
	if err != nil {
		return nil, err
	}

	raw := make([]bpf.RawInstruction, len(pcapBPF))
	for i, ri := range pcapBPF {
		raw[i] = bpf.RawInstruction{Op: ri.Code, Jt: ri.Jt, Jf: ri.Jf, K: ri.K}
	}

	return raw, nil
}

func (c *Collector) printlnStdOut(args ...interface{}) {
	if c.config.DecoderConfig.Quiet {
		_, _ = fmt.Fprintln(c.netcapLogFile, args...)
	} else {
		_, _ = fmt.Fprintln(c.netcapLogFile, args...)
		_, _ = fmt.Fprintln(os.Stdout, args...)
	}
}

func (c *Collector) printStdOut(args ...interface{}) {
	if c.config.DecoderConfig.Quiet {
		_, _ = fmt.Fprint(c.netcapLogFile, args...)
	} else {
		_, _ = fmt.Fprint(os.Stdout, args...)
	}
}
