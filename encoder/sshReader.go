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
	"encoding/binary"
	"fmt"
	"github.com/davecgh/go-spew/spew"
	"github.com/dreadl0ck/gopacket"
	"github.com/dreadl0ck/netcap/reassembly"
	"github.com/dreadl0ck/netcap/sshx"
	"github.com/dreadl0ck/netcap/utils"
	"github.com/mgutz/ansi"
	"io"
	"sort"
	"time"
)

/*
 * TCP
 */

type sshReader struct {
	ident    string
	isClient bool
	dataChan chan *Data
	data     []*Data
	merged   DataSlice
	hexdump  bool
	parent   *tcpConnection

	numBytes int

	serviceBanner      bytes.Buffer
	serviceBannerBytes int

	saved bool
}

func (h *sshReader) Read(p []byte) (int, error) {

	var (
		ok = true
		data *Data
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

func (h *sshReader) DataChan() chan *Data {
	return h.dataChan
}

func (h *sshReader) Cleanup(f *tcpConnectionFactory, s2c Connection, c2s Connection) {

	// fmt.Println("TCP cleanup", h.ident)

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
		// TODO
	}

	// signal wait group
	f.wg.Done()
	f.Lock()
	f.numActive--
	f.Unlock()
}

// run starts decoding POP3 traffic in a single direction
func (h *sshReader) Run(f *tcpConnectionFactory) {

	// create streams
	var (
		// client to server
		c2s = Connection{h.parent.net, h.parent.transport}
		// server to client
		s2c = Connection{h.parent.net.Reverse(), h.parent.transport.Reverse()}
	)

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

			utils.ReassemblyLog.Println("TCP stream encountered an error", c2s, err)

			// stop processing the stream and trigger cleanup
			return
		}
	}
}

func (h *sshReader) readStream(b *bufio.Reader) error {

	data, _, err := b.ReadLine()
	if err == io.EOF || err == io.ErrUnexpectedEOF {
		return err
	} else if err != nil {
		logReassemblyError("readStream", "TCP/%s failed to read: %s (%v,%+v)\n", h.ident, err)
		return err
	}

	if h.isClient {

		//fmt.Println(hex.Dump(data))

		for i, b := range data {

			if b == 0x14 { // Marks the beginning of the KexInitMsg

				if i == 0 {
					break
				}

				if len(data[:i-1]) != 4 {
					break
				}

				length := int(binary.BigEndian.Uint32(data[:i-1]))
				padding := int(data[i-1])

				if len(data) < i+length-padding-1 {
					break
				}

				//fmt.Println("padding", padding, "length", length)
				//fmt.Println(hex.Dump(data[i:i+length-padding-1]))

				var init sshx.KexInitMsg
				err = sshx.Unmarshal(data[i:i+length-padding-1], &init)
				if err != nil {
					fmt.Println(err)
				}

				spew.Dump(init)
				break
			}
		}
	}

	return nil
}

func (h *sshReader) DataSlice() DataSlice {
	return h.data
}

func (h *sshReader) ClientStream() []byte {
	h.parent.Lock()
	defer h.parent.Unlock()
	return nil // h.clientData.Bytes()
}

func (h *sshReader) ServerStream() []byte {
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

func (h *sshReader) ConversationRaw() []byte {

	h.parent.Lock()
	defer h.parent.Unlock()

	// do this only once, this method will be called once for each side of a connection
	if len(h.merged) == 0 {

		// concatenate both client and server data fragments
		h.merged = append(h.parent.client.DataSlice(), h.parent.server.DataSlice()...)

		// sort based on their timestamps
		sort.Sort(h.merged)

		// create the buffer with the entire conversation
		for _, c := range h.merged {
			//fmt.Println(h.ident, c.ac.GetCaptureInfo().Timestamp, c.ac.GetCaptureInfo().Length)

			h.parent.conversationRaw.Write(c.raw)
			if c.dir == reassembly.TCPDirClientToServer {
				h.parent.conversationColored.WriteString(ansi.Red + string(c.raw) + ansi.Reset)
			} else {
				h.parent.conversationColored.WriteString(ansi.Blue + string(c.raw) + ansi.Reset)
			}
		}
	}

	return h.parent.conversationRaw.Bytes()
}

func (h *sshReader) ConversationColored() []byte {
	h.parent.Lock()
	defer h.parent.Unlock()
	return h.parent.conversationColored.Bytes()
}

func (h *sshReader) IsClient() bool {
	return h.isClient
}

func (h *sshReader) Ident() string {
	return h.parent.ident
}
func (h *sshReader) Network() gopacket.Flow {
	return h.parent.net
}
func (h *sshReader) Transport() gopacket.Flow {
	return h.parent.transport
}
func (h *sshReader) FirstPacket() time.Time {
	return h.parent.firstPacket
}

func (h *sshReader) Saved() bool {
	h.parent.Lock()
	defer h.parent.Unlock()
	return h.saved
}

func (h *sshReader) MarkSaved() {
	h.parent.Lock()
	defer h.parent.Unlock()
	h.saved = true
}

func (h *sshReader) NumBytes() int {
	h.parent.Lock()
	defer h.parent.Unlock()
	return h.numBytes
}

func (h *sshReader) Client() StreamReader {
	return h.parent.client.(StreamReader)
}

func (h *sshReader) SetClient(v bool) {
	h.isClient = v
}

func (h *sshReader) ServiceBanner() []byte {
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