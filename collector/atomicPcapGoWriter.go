/*
 * NETCAP - Network Capture Framework
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
	"sync"
	"sync/atomic"

	"github.com/dreadl0ck/gopacket"
	"github.com/dreadl0ck/gopacket/pcapgo"
)

//////////////////////////
// Atomic PcapGo Writer //
//////////////////////////

// AtomicPcapGoWriter is a symchronized PCAP writer
// that counts the number of packets written.
type AtomicPcapGoWriter struct {
	count int64
	w     pcapgo.Writer
	sync.Mutex
}

// WritePacket writes a packet into the writer.
func (a *AtomicPcapGoWriter) WritePacket(ci gopacket.CaptureInfo, data []byte) error {
	// sync
	a.Lock()
	err := a.w.WritePacket(ci, data)
	// dont use a defer here for performance
	a.Unlock()

	atomic.AddInt64(&a.count, 1)
	return err
}

// NewAtomicPcapGoWriter takes a pcapgo.Writer and returns an atomic version
func NewAtomicPcapGoWriter(w *pcapgo.Writer) *AtomicPcapGoWriter {
	return &AtomicPcapGoWriter{
		w: *w,
	}
}
