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
	"io"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/mgutz/ansi"
)

/*
 * TCP
 */

// TODO: make configurable
var logTCPDebug = true

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
		// time out streams that never send any data
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

func (h *tcpReader) Cleanup(wg *sync.WaitGroup, s2c Connection, c2s Connection) {

	// fmt.Println("POP3 cleanup", h.ident)

	// determine if one side of the stream has already been closed
	h.parent.Lock()
	if !h.parent.last {

		// signal wait group
		wg.Done()

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
	wg.Done()
}

// run starts decoding POP3 traffic in a single direction
func (h *tcpReader) Run(wg *sync.WaitGroup) {

	// create streams
	var (
		// client to server
		c2s = Connection{h.parent.net, h.parent.transport}
		// server to client
		s2c = Connection{h.parent.net.Reverse(), h.parent.transport.Reverse()}
	)

	// defer a cleanup func to flush the requests and responses once the stream encounters an EOF
	defer h.Cleanup(wg, s2c, c2s)

	var (
		err error
		b   = bufio.NewReader(h)
	)
	for {
		if h.isClient {
			// client request
			err = h.readBanner(b, c2s)
		} else {
			// server response
			err = h.readBanner(b, s2c)
		}
		if err != nil {

			// exit on EOF
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				return
			}

			reassemblyLog.Println("TCP stream encountered an error", c2s, err)

			// continue processing the stream
			continue
		}
	}
}

func (h *tcpReader) getServiceName(data []byte) string {

	dstPort, _ := strconv.Atoi(h.parent.transport.Dst().String())
	srcPort, _ := strconv.Atoi(h.parent.transport.Src().String())

	s := resolvers.LookupServiceByPort(srcPort, "tcp")
	if s != "" && s != "Reserved" {
		return filepath.Clean(strings.ReplaceAll(s, " ", "-"))
	}
	s = resolvers.LookupServiceByPort(dstPort, "tcp")
	if s != "" && s != "Reserved" {
		return filepath.Clean(strings.ReplaceAll(s, " ", "-"))
	}

	if utf8.ValidString(string(data)) {
		return "utf8"
	}
	return "unknown"
}

func (h *tcpReader) saveBanner(data []byte) error {

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
	if len(base) > 250 {
		base = base[:250] + "..."
	}
	if base == FileStorage {
		base = path.Join(FileStorage, "noname")
	}
	var (
		target = base
		n      = 0
	)
	for {
		// prevent overwriting files - duplicates will be enumerated
		_, errStat := os.Stat(target)
		if errStat != nil {
			break
		}

		target = path.Join(root, filepath.Clean(h.ident)+"-"+strconv.Itoa(n))
		n++
	}

	//fmt.Println("saving file:", target)

	f, err := os.Create(target)
	if err != nil {
		logReassemblyError("TCP Banner create", "Cannot create %s: %s\n", target, err)
		return err
	}

	// now assign a new buffer
	r := bytes.NewBuffer(data)
	w, err := io.Copy(f, r)
	if err != nil {
		logReassemblyError("TCP Banner", "%s: failed to save TCP banner %s (l:%d): %s\n", h.ident, target, w, err)
	} else {
		logReassemblyInfo("%s: Saved TCP Banner %s (l:%d)\n", h.ident, target, w)
	}

	err = f.Close()
	if err != nil {
		logReassemblyError("TCP Banner", "%s: failed to close TCP banner file %s (l:%d): %s\n", h.ident, target, w, err)
	}

	// TODO: write Banner audit record to disk
	//writeBanner(&types.Banner{
	// ...
	//	Timestamp:   h.parent.firstPacket.String(),
	//	Name:        fileName,
	//	Length:      int64(len(body)),
	//	Hash:        hex.EncodeToString(cryptoutils.MD5Data(body)),
	//	Location:    target,
	//	Ident:       h.ident,
	//	Source:      source,
	//	ContentType: ctype,
	//	Context: &types.PacketContext{
	//		SrcIP:   h.parent.net.Src().String(),
	//		DstIP:   h.parent.net.Dst().String(),
	//		SrcPort: h.parent.transport.Src().String(),
	//		DstPort: h.parent.transport.Dst().String(),
	//	},
	//})

	return nil
}

func tcpDebug(args ...interface{}) {
	if logTCPDebug {
		debugLog.Println(args...)
	}
}

func (h *tcpReader) readBanner(b *bufio.Reader, s2c Connection) error {

	// Parse the first line of the response.
	data, err := ioutil.ReadAll(b)
	if err == io.EOF || err == io.ErrUnexpectedEOF {
		return err
	} else if err != nil {
		logReassemblyError("readBanner", "TCP/%s failed to read banner: %s (%v,%+v)\n", h.ident, err, err, err)
		return err
	}

	tcpDebug(ansi.Blue, h.ident, "readBanner: read", len(data), "bytes", ansi.Reset)

	return h.saveBanner(data)
}
