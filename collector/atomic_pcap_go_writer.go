/*
 * NETCAP - Network Capture Framework
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
	"sync"
	"sync/atomic"

	"github.com/dreadl0ck/gopacket"
	"github.com/dreadl0ck/gopacket/pcapgo"
)

// atomicPcapGoWriter is a synchronized PCAP writer
// that counts the number of packets written.
type atomicPcapGoWriter struct {
	sync.Mutex
	count int64
	w     pcapgo.Writer
	err   error
}

// writePacket writes a packet into the writer.
func (a *atomicPcapGoWriter) writePacket(ci gopacket.CaptureInfo, data []byte) error {
	// ensure synchronous access
	a.Lock()

	// reuse the error on writer to avoid reallocation
	a.err = a.w.WritePacket(ci, data)

	// don't use a defer for unlocking to improve performance
	a.Unlock()

	// atomically increase the audit record counter
	atomic.AddInt64(&a.count, 1)

	return a.err
}

// newAtomicPcapGoWriter takes a pcapgo.Writer and returns an atomic version.
func newAtomicPcapGoWriter(w *pcapgo.Writer) *atomicPcapGoWriter {
	return &atomicPcapGoWriter{
		w: *w,
	}
}
