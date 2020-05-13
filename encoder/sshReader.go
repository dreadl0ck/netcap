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
	"github.com/dreadl0ck/gopacket"
	"github.com/dreadl0ck/netcap/sshx"
	"github.com/dreadl0ck/netcap/utils"
	"github.com/mgutz/ansi"
	"io"
	"time"
)

/*
 * TCP
 */

type sshReader struct {
	ident    string
	isClient bool
	bytes    chan []byte
	data     []byte
	hexdump  bool
	parent   *tcpConnection

	numBytes int

	serviceBanner      bytes.Buffer
	serviceBannerBytes int

	saved bool
}

func (h *sshReader) Read(p []byte) (int, error) {
	ok := true
	for ok && len(h.data) == 0 {
		select {
		case h.data, ok = <-h.bytes:
		}
	}
	if !ok || len(h.data) == 0 {
		return 0, io.EOF
	}

	l := copy(p, h.data)
	h.numBytes += l
	h.data = h.data[l:]

	dataCpy := p[:l]

	h.parent.Lock()

	// write raw
	h.parent.conversationRaw.Write(dataCpy)

	// colored for debugging
	if h.isClient {
		h.parent.conversationColored.WriteString(ansi.Red + string(dataCpy) + ansi.Reset)
	} else {
		h.parent.conversationColored.WriteString(ansi.Blue + string(dataCpy) + ansi.Reset)
	}

	// save server stream for banner identification
	// stores c.BannerSize number of bytes of the server side stream
	if !h.isClient && h.serviceBannerBytes < c.BannerSize {
		for _, b := range dataCpy {
			h.serviceBanner.WriteByte(b)
			h.serviceBannerBytes++
			if h.serviceBannerBytes == c.BannerSize {
				break
			}
		}
	}
	h.parent.Unlock()

	return l, nil
}

func (h *sshReader) BytesChan() chan []byte {
	return h.bytes
}

func (h *sshReader) Cleanup(f *tcpConnectionFactory, s2c Connection, c2s Connection) {

	// fmt.Println("TCP cleanup", h.ident)
	h.parent.Lock()
	h.saved = true
	h.parent.Unlock()

	// save data for the current stream
	if h.isClient {
		err := saveConnection(h.ConversationRaw(), h.ConversationColored(), h.Ident(), h.FirstPacket(), h.Transport())
		if err != nil {
			fmt.Println("failed to save stream", err)
		}
	} else {
		saveTCPServiceBanner(h.serviceBanner.Bytes(), h.parent.ident, h.parent.firstPacket, h.parent.net, h.parent.transport, h.numBytes, h.parent.client.(StreamReader).NumBytes())
	}

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
		if h.isClient {
			// read client request until EOF
			err = h.readStream(b)
		} else {
			// read server response until EOF
			err = h.readStream(b)
		}
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

				//spew.Dump(init)
				break
			}
		}
	}

	return nil
}

func (h *sshReader) ClientStream() []byte {
	h.parent.Lock()
	defer h.parent.Unlock()
	return nil // h.clientData.Bytes()
}

func (h *sshReader) ServerStream() []byte {
	h.parent.Lock()
	defer h.parent.Unlock()
	return h.serviceBanner.Bytes()
}

func (h *sshReader) ConversationRaw() []byte {
	h.parent.Lock()
	defer h.parent.Unlock()
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

func (h *sshReader) NumBytes() int {
	h.parent.Lock()
	defer h.parent.Unlock()
	return h.numBytes
}

func (h *sshReader) Client() StreamReader {
	return h.parent.client.(StreamReader)
}
