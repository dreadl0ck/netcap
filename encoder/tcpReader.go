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
	"github.com/dreadl0ck/netcap/resolvers"
	"github.com/dreadl0ck/netcap/utils"
	"io"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"time"
	"unicode/utf8"
)

/*
 * TCP
 */

type tcpReader struct {
	ident    string
	isClient bool
	bytes    chan []byte
	data     []byte
	hexdump  bool
	parent   *tcpConnection
}

func (h *tcpReader) Read(p []byte) (int, error) {
	ok := true
	for ok && len(h.data) == 0 {
		select {
		case h.data, ok = <-h.bytes:
		case <-time.After(c.ClosePendingTimeOut):
			return 0, io.EOF
		}
	}
	if !ok || len(h.data) == 0 {
		return 0, io.EOF
	}

	l := copy(p, h.data)
	h.data = h.data[l:]
	return l, nil
}

func (h *tcpReader) BytesChan() chan []byte {
	return h.bytes
}

func (h *tcpReader) Cleanup(f *tcpConnectionFactory, s2c Connection, c2s Connection) {

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
func (h *tcpReader) Run(f *tcpConnectionFactory) {

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

func (h *tcpReader) getServiceName(data []byte) string {

	var (
		dstPort, _ = strconv.Atoi(h.parent.transport.Dst().String())
		s          = resolvers.LookupServiceByPort(dstPort, "tcp")
	)
	if s != "" {
		return s
	}

	if utf8.ValidString(string(data)) {
		return "utf8"
	}
	return "unknown"
}

func (h *tcpReader) saveStream(data []byte) error {

	// prevent saving zero bytes
	if len(data) == 0 {
		return nil
	}

	var (
		typ = h.getServiceName(data)

		// path for storing the data
		root = filepath.Join(c.Out, "tcpstreams", typ)

		// file basename
		base = filepath.Clean(path.Base(h.ident)) + ".bin"
	)

	// make sure root path exists
	os.MkdirAll(root, directoryPermission)
	base = path.Join(root, base)

	utils.ReassemblyLog.Println("saveStream", base)

	statsMutex.Lock()
	reassemblyStats.savedStreams++
	statsMutex.Unlock()

	// append to files
	f, err := os.OpenFile(base, os.O_CREATE|os.O_WRONLY|os.O_APPEND|os.O_SYNC, 0700)
	if err != nil {
		logReassemblyError("TCP stream create", "Cannot create %s: %s\n", base, err)
		return err
	}

	// now assign a new buffer
	r := bytes.NewBuffer(data)
	w, err := io.Copy(f, r)
	if err != nil {
		logReassemblyError("TCP stream", "%s: failed to save TCP stream %s (l:%d): %s\n", h.ident, base, w, err)
	} else {
		logReassemblyInfo("%s: Saved TCP stream %s (l:%d)\n", h.ident, base, w)
	}

	err = f.Close()
	if err != nil {
		logReassemblyError("TCP stream", "%s: failed to close TCP stream file %s (l:%d): %s\n", h.ident, base, w, err)
	}

	if !h.isClient {
		saveTCPServiceBanner(h, data)
	}

	return nil
}

func tcpDebug(args ...interface{}) {
	if c.TCPDebug {
		utils.DebugLog.Println(args...)
	}
}

func (h *tcpReader) readStreamBuffered(b *bufio.Reader) error {

	// read 512kB chunks of data
	var (
		// the data buffer that we will return from this call
		// initialize empty with a capacity of 512
		data = make([]byte, 0, 512)

		// the intermediate buffer used for each Read invocation
		readbuf = make([]byte, 512)
	)

	for {
		// Careful: using ioutil.ReadAll here causes a data race!
		// alternatively:
		// n, err := io.ReadFull(b, data) // will wait forever if the flow sends less than 512 bytes of data or never sends an EOF

		n, err := b.Read(readbuf)
		//fmt.Println(ansi.Blue, h.ident, "readStream: read", n, "bytes (total", len(data), ")", err, ansi.Reset)
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			break
		} else if err != nil {
			logReassemblyError("readStream", "TCP/%s failed to read: %s (%v,%+v)\n", h.ident, err)
			return err
		}

		// if we got the buffer full, stop
		if n == 512 {
			data = readbuf

			// done
			break
		} else {

			// if we got less, buffer the data and keep reading
			data = append(data, readbuf[:n]...)
		}

		// throttle?
		//time.Sleep(100 * time.Millisecond)
	}

	return h.saveStream(data)
}

func (h *tcpReader) readStream(b *bufio.Reader) error {

	var data = make([]byte, 512)

	n, err := b.Read(data)
	if err == io.EOF || err == io.ErrUnexpectedEOF {
		return err
	} else if err != nil {
		logReassemblyError("readBanner", "TCP/%s failed to read: %s (%v,%+v)\n", h.ident, err)
		return err
	}
	h.saveStream(data[:n])
	return nil
}
