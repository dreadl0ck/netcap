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
	"fmt"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"golang.org/x/net/bpf"
)

// printProgressLive prints live statistics.
func (c *Collector) printProgressLive() {
	// must be locked, otherwise a race occurs when sending a SIGINT and triggering wg.Wait() in another goroutine...
	c.statMutex.Lock()
	c.wg.Add(1)
	c.statMutex.Unlock()

	atomic.AddInt64(&c.current, 1)
	if c.current%1000 == 0 {
		clearLine()
		fmt.Print("running since ", time.Since(c.start), ", captured ", c.current, " packets...")
	}
}

// DumpProto prints a protobuff Message.
func DumpProto(pb proto.Message) {
	println(proto.MarshalTextString(pb))
}

func clearLine() {
	print("\033[2K\r")
}

func share(current, total int64) string {
	percent := (float64(current) / float64(total)) * 100
	return strconv.FormatFloat(percent, 'f', 5, 64) + "%"
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
