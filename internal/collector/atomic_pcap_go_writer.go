/*
 * NETCAP - Network Capture Framework
 * Copyright (c) 2017-2025 Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
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
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

type atomicPcapGoWriter struct {
	sync.Mutex
	count      int64
	w          io.Writer
	link       layers.LinkType
	order      binary.ByteOrder
	interfaces map[diagnosticInterface]uint32
	err        error
}

type diagnosticInterface struct {
	index int
	link  layers.LinkType
}

func (a *atomicPcapGoWriter) writePacket(ci gopacket.CaptureInfo, data []byte) (err error) {
	a.Lock()
	defer a.Unlock()
	if a.err != nil {
		return a.err
	}
	defer func() { a.err = err }()
	link := a.link
	if len(ci.AncillaryData) > 0 {
		if lt, ok := ci.AncillaryData[0].(layers.LinkType); ok {
			link = lt
		}
	}
	order := inputPacketInfo(ci).Order
	if order == nil {
		order = binary.LittleEndian
	}
	if len(data) > maxInputPacket || ci.CaptureLength != len(data) || ci.Length < len(data) {
		return fmt.Errorf("invalid diagnostic packet lengths")
	}
	if !ci.Timestamp.IsZero() && !supportedRetentionTimestamp(ci.Timestamp) {
		return fmt.Errorf("diagnostic timestamp is outside the supported Unix nanosecond range")
	}
	if a.order != order || ci.Timestamp.IsZero() {
		a.order = order
		a.interfaces = make(map[diagnosticInterface]uint32)
		body := make([]byte, 16)
		order.PutUint32(body, 0x1a2b3c4d)
		order.PutUint16(body[4:], 1)
		order.PutUint64(body[8:], ^uint64(0))
		if err := a.block(ngSection, body); err != nil {
			return err
		}
	}
	key := diagnosticInterface{ci.InterfaceIndex, link}
	id, ok := a.interfaces[key]
	if !ok {
		if len(a.interfaces) >= maxInputInterfaces {
			return fmt.Errorf("diagnostic interface limit exceeded")
		}
		id = uint32(len(a.interfaces))
		name := []byte(fmt.Sprintf("capture-interface-%d", ci.InterfaceIndex))
		body := make([]byte, 24+((len(name)+3)&^3))
		order.PutUint16(body, uint16(link))
		order.PutUint32(body[4:], maxInputPacket)
		order.PutUint16(body[8:], 9) // if_tsresol: nanoseconds
		order.PutUint16(body[10:], 1)
		body[12] = 9
		order.PutUint16(body[16:], 2) // if_name preserves the source ordinal.
		order.PutUint16(body[18:], uint16(len(name)))
		copy(body[20:], name)
		if err := a.block(1, body); err != nil {
			return err
		}
		a.interfaces[key] = id
	}
	kind, header := uint32(6), 20
	if ci.Timestamp.IsZero() {
		kind, header = 3, 4
		if ci.Length != len(data) {
			return fmt.Errorf("cannot retain timestamp-less truncated diagnostic packet")
		}
	}
	body := make([]byte, header+((len(data)+3)&^3))
	if kind == 3 {
		order.PutUint32(body, uint32(ci.Length))
	} else {
		stamp := uint64(ci.Timestamp.UnixNano())
		order.PutUint32(body, id)
		order.PutUint32(body[4:], uint32(stamp>>32))
		order.PutUint32(body[8:], uint32(stamp))
		order.PutUint32(body[12:], uint32(len(data)))
		order.PutUint32(body[16:], uint32(ci.Length))
	}
	copy(body[header:], data)
	if err := a.block(kind, body); err != nil {
		return err
	}
	atomic.AddInt64(&a.count, 1)
	return nil
}

func supportedRetentionTimestamp(t time.Time) bool {
	seconds := t.Unix()
	return seconds >= 0 && (seconds < math.MaxInt64/1_000_000_000 ||
		(seconds == math.MaxInt64/1_000_000_000 && int64(t.Nanosecond()) <= math.MaxInt64%1_000_000_000))
}

func (a *atomicPcapGoWriter) failure() error {
	if a == nil {
		return nil
	}
	a.Lock()
	defer a.Unlock()
	return a.err
}

// Diagnostic files retain their historical .pcap names but contain PCAPNG so
// mixed link types and native-endian NFLOG frames are never labelled Ethernet.
func newAtomicPcapGoWriter(w io.Writer, link layers.LinkType) *atomicPcapGoWriter {
	return &atomicPcapGoWriter{w: w, link: link}
}

func (a *atomicPcapGoWriter) block(kind uint32, body []byte) error {
	block := make([]byte, len(body)+12)
	a.order.PutUint32(block, kind)
	a.order.PutUint32(block[4:], uint32(len(block)))
	copy(block[8:], body)
	a.order.PutUint32(block[len(block)-4:], uint32(len(block)))
	n, err := a.w.Write(block)
	if err == nil && n != len(block) {
		err = io.ErrShortWrite
	}
	return err
}
