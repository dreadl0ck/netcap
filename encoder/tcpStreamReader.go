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

package encoder

import (
	"bufio"
	"bytes"
	"fmt"
	"github.com/dreadl0ck/gopacket"
	"github.com/dreadl0ck/netcap/utils"
	"io"
	"path/filepath"
	"sync"
	"time"
)

// internal structure that is used to read TCP data streams
// this structure has an optimized field order to avoid excessive padding
type tcpStreamReader struct {
	serviceBanner      bytes.Buffer
	data               []*StreamData
	ident              string
	parent             *tcpConnection
	numBytes           int
	dataChan           chan *StreamData
	serviceBannerBytes int
	hexdump            bool
	isClient           bool
	saved              bool
	sync.Mutex
}

func newTCPStreamReader(parent *tcpConnection, ident string, client bool) *tcpStreamReader {
	return &tcpStreamReader{
		dataChan: make(chan *StreamData, c.StreamDecoderBufSize),
		ident:    ident,
		hexdump:  c.HexDump,
		parent:   parent,
		isClient: client,
	}
}

func (h *tcpStreamReader) Read(p []byte) (int, error) {

	var (
		ok   = true
		data *StreamData
	)

	data, ok = <-h.dataChan
	if data == nil || !ok {
		return 0, io.EOF
	}

	// copy received data into the passed in buffer
	l := copy(p, data.raw)

	h.parent.Lock()
	h.data = append(h.data, data)
	h.numBytes += l
	h.parent.Unlock()

	return l, nil
}

func (h *tcpStreamReader) DataChan() chan *StreamData {
	return h.dataChan
}

func (h *tcpStreamReader) Cleanup(f *tcpConnectionFactory, s2c Stream, c2s Stream) {

	// determine if one side of the stream has already been closed
	h.parent.Lock()
	if !h.parent.last {

		// signal wait group
		f.wg.Done()
		f.Lock()
		f.numActive--
		f.Unlock()

		// indicate close on the parent tcpConnection
		h.parent.last = true

		// free lock
		h.parent.Unlock()

		return
	}
	h.parent.Unlock()

	// cleanup() is called twice - once for each direction of the stream
	// this check ensures the audit record collection is executed only if one side has been closed already
	// to ensure all necessary requests and responses are present
	if h.parent.last {
		//TODO:
	}

	// signal wait group
	f.wg.Done()
	f.Lock()
	f.numActive--
	f.Unlock()
}

func (h *tcpStreamReader) DataSlice() StreamDataSlice {
	return h.data
}

func (h *tcpStreamReader) ClientStream() []byte {
	var buf bytes.Buffer

	h.parent.Lock()
	defer h.parent.Unlock()

	// stores c.BannerSize number of bytes of the server side stream
	for _, d := range h.parent.client.DataSlice() {
		for _, b := range d.raw {
			buf.WriteByte(b)
		}
	}

	return buf.Bytes()
}

func (h *tcpStreamReader) ServerStream() []byte {
	var buf bytes.Buffer

	h.parent.Lock()
	defer h.parent.Unlock()

	// save server stream for banner identification
	// stores c.BannerSize number of bytes of the server side stream
	for _, d := range h.parent.server.DataSlice() {
		for _, b := range d.raw {
			buf.WriteByte(b)
		}
	}

	return buf.Bytes()
}

func (h *tcpStreamReader) ConversationRaw() []byte {
	return h.parent.ConversationRaw()
}

func (h *tcpStreamReader) ConversationColored() []byte {
	return h.parent.ConversationColored()
}

func (h *tcpStreamReader) IsClient() bool {
	return h.isClient
}

func (h *tcpStreamReader) Ident() string {
	return h.parent.ident
}
func (h *tcpStreamReader) Network() gopacket.Flow {
	return h.parent.net
}
func (h *tcpStreamReader) Transport() gopacket.Flow {
	return h.parent.transport
}
func (h *tcpStreamReader) FirstPacket() time.Time {
	return h.parent.firstPacket
}
func (h *tcpStreamReader) Saved() bool {
	h.parent.Lock()
	defer h.parent.Unlock()
	return h.saved
}

func (h *tcpStreamReader) NumBytes() int {
	h.Lock()
	defer h.Unlock()
	return h.numBytes
}

func (h *tcpStreamReader) Client() StreamReader {
	return h.parent.client
}

func (h *tcpStreamReader) SetClient(v bool) {
	h.parent.Lock()
	defer h.parent.Unlock()
	h.isClient = v
}

func (h *tcpStreamReader) MarkSaved() {
	h.parent.Lock()
	defer h.parent.Unlock()
	h.saved = true
}

func (h *tcpStreamReader) ServiceIdent() string {
	h.parent.Lock()
	defer h.parent.Unlock()
	return filepath.Clean(fmt.Sprintf("%s->%s", h.parent.server.Network().Dst(), h.parent.server.Transport().Dst()))
}

func (h *tcpStreamReader) ServiceBanner() []byte {
	h.parent.Lock()
	defer h.parent.Unlock()

	if h.serviceBanner.Len() == 0 {
		// save server stream for banner identification
		// stores c.BannerSize number of bytes of the server side stream
		for _, d := range h.parent.server.DataSlice() {
			for _, b := range d.raw {
				h.serviceBanner.WriteByte(b)
				h.serviceBannerBytes++
				if h.serviceBannerBytes == c.BannerSize {
					break
				}
			}
		}
	}

	return h.serviceBanner.Bytes()
}

// run starts reading TCP traffic in a single direction
func (h *tcpStreamReader) Run(f *tcpConnectionFactory) {

	h.parent.Lock()
	// create streams
	var (
		// client to server
		c2s = Stream{h.parent.net, h.parent.transport}
		// server to client
		s2c = Stream{h.parent.net.Reverse(), h.parent.transport.Reverse()}
	)
	h.parent.Unlock()

	// defer a cleanup func to flush the requests and responses once the stream encounters an EOF
	defer h.Cleanup(f, s2c, c2s)

	var (
		err error
		b   = bufio.NewReader(h)
	)
	for {
		err = h.readStream(b)
		if err != nil {

			// exit on EOF
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				return
			}

			utils.ReassemblyLog.Println("TCP stream encountered an error", h.parent.ident, err)
			fmt.Println("TCP stream encountered an error", h.parent.ident, err)

			// stop processing the stream and trigger cleanup
			return
		}
	}
}

func (h *tcpStreamReader) readStream(b *bufio.Reader) error {

	var err error
	for {
		_, err = b.ReadByte()
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			return err
		} else if err != nil {
			logReassemblyError("readStream", "TCP/%s failed to read: %s (%v,%+v)\n", h.ident, err)
			return err
		}
	}
}
