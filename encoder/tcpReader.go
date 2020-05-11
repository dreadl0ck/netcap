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
	"io"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"time"
	"unicode"

	"github.com/dreadl0ck/gopacket"
	"github.com/dreadl0ck/netcap/resolvers"
	"github.com/dreadl0ck/netcap/utils"
	"github.com/mgutz/ansi"
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

	serviceBanner      bytes.Buffer
	serviceBannerBytes int

	saved bool
}

func (h *tcpReader) Read(p []byte) (int, error) {
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

func (h *tcpReader) BytesChan() chan []byte {
	return h.bytes
}

func (h *tcpReader) Cleanup(f *tcpConnectionFactory, s2c Connection, c2s Connection) {

	// fmt.Println("TCP cleanup", h.ident)

	// save data for the current stream
	if h.isClient {
		err := saveConnection(h.ConversationRaw(), h.ConversationColored(), h.Ident(), h.FirstPacket(), h.Transport())
		if err != nil {
			fmt.Println("failed to save stream", err)
		}
		h.saved = true
	} else {
		saveTCPServiceBanner(h.serviceBanner.Bytes(), h.parent.ident, h.parent.firstPacket, h.parent.net, h.parent.transport)
		h.saved = true
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

func getServiceName(data []byte, flow gopacket.Flow) string {

	var (
		dstPort, _ = strconv.Atoi(flow.Dst().String())
		s          = resolvers.LookupServiceByPort(dstPort, "tcp")
	)
	if s != "" {
		return s
	}

	// what about the source port?
	srcPort, _ := strconv.Atoi(flow.Src().String())
	s = resolvers.LookupServiceByPort(srcPort, "tcp")
	if s != "" {
		return s
	}

	// still no clue? lets check if its ascii
	if isAscii(data) {
		return "ascii"
	}

	return "unknown"
}

// checks if input consists of ascii characters
func isAscii(d []byte) bool {
	if len(d) == 0 {
		return false
	}
	for i := 0; i < len(d); i++ {
		if d[i] > unicode.MaxASCII {
			return false
		}
	}
	return true
}

func runHarvesters(raw []byte, transport gopacket.Flow, ident string, firstPacket time.Time) []byte {

	// TODO: only use harvesters when credential audit record type is loaded!

	var (
		banner = make([]byte, 0, c.BannerSize)
		found  bool
		tried  *CredentialHarvester
	)

	// copy c.BannerSize number of bytes from the raw conversation
	// to use for the credential harvesters
	for i, b := range raw {
		if i >= c.BannerSize {
			break
		}
		banner = append(banner, b)
	}

	// convert service port to integer
	dstPort, err := strconv.Atoi(transport.Dst().String())
	if err != nil {
		fmt.Println(err)
	}

	srcPort, err := strconv.Atoi(transport.Src().String())
	if err != nil {
		fmt.Println(err)
	}

	// check if its a well known port and use the harvester for that one
	if ch, ok := harvesterPortMapping[dstPort]; ok {
		if c := ch(banner, ident, firstPacket); c != nil {

			// write audit record
			writeCredentials(c)

			// we found a match and will stop processing
			// TODO: make configurable
			found = true
		} else {
			// save the address of the harvester function
			// we dont need to run it again
			tried = &ch
		}
	}

	if ch, ok := harvesterPortMapping[srcPort]; ok {
		if c := ch(banner, ident, firstPacket); c != nil {

			// write audit record
			writeCredentials(c)

			// we found a match and will stop processing
			// TODO: make configurable
			found = true
		} else {
			// save the address of the harvester function
			// we dont need to run it again
			tried = &ch
		}
	}

	// if we dont have a match yet, match against all available harvesters
	if !found {

		// iterate over all harvesters
		for _, ch := range tcpConnectionHarvesters {

			// if the port based first guess has not been found, do not run this harvester again
			if &ch != tried {

				// execute harvester
				if c := ch(banner, ident, firstPacket); c != nil {

					// write audit record
					writeCredentials(c)

					// stop after a match for now
					// TODO: make configurable
					break
				}
			}
		}
	}

	return banner
}

func saveConnection(raw []byte, colored []byte, ident string, firstPacket time.Time, transport gopacket.Flow) error {

	// prevent processing zero bytes
	if len(raw) == 0 {
		return nil
	}

	banner := runHarvesters(raw, transport, ident, firstPacket)

	if !c.SaveConns {
		return nil
	}

	//fmt.Println("save conn", ident, len(raw), len(colored))
	//fmt.Println(string(colored))

	var (
		typ = getServiceName(banner, transport)

		// path for storing the data
		root = filepath.Join(c.Out, "tcpConnections", typ)

		// file basename
		base = filepath.Clean(path.Base(ident)) + ".bin"
	)

	// make sure root path exists
	os.MkdirAll(root, directoryPermission)
	base = path.Join(root, base)

	utils.ReassemblyLog.Println("saveConnection", base)

	statsMutex.Lock()
	reassemblyStats.savedConnections++
	statsMutex.Unlock()

	// append to files
	f, err := os.OpenFile(base, os.O_CREATE|os.O_WRONLY|os.O_APPEND|os.O_SYNC, 0700)
	if err != nil {
		logReassemblyError("TCP conn create", "Cannot create %s: %s\n", base, err)
		return err
	}

	// save the colored version
	// assign a new buffer
	r := bytes.NewBuffer(colored)
	w, err := io.Copy(f, r)
	if err != nil {
		logReassemblyError("TCP stream", "%s: failed to save TCP conn %s (l:%d): %s\n", ident, base, w, err)
	} else {
		logReassemblyInfo("%s: Saved TCP conn %s (l:%d)\n", ident, base, w)
	}

	err = f.Close()
	if err != nil {
		logReassemblyError("TCP conn", "%s: failed to close TCP conn file %s (l:%d): %s\n", ident, base, w, err)
	}

	return nil
}

func tcpDebug(args ...interface{}) {
	if c.TCPDebug {
		utils.DebugLog.Println(args...)
	}
}

func (h *tcpReader) readStream(b *bufio.Reader) error {

	var data = make([]byte, 512)

	_, err := b.Read(data)
	if err == io.EOF || err == io.ErrUnexpectedEOF {
		return err
	} else if err != nil {
		logReassemblyError("readStream", "TCP/%s failed to read: %s (%v,%+v)\n", h.ident, err)
		return err
	}

	return nil
}

func (h *tcpReader) ClientStream() []byte {
	h.parent.Lock()
	defer h.parent.Unlock()
	return nil // h.clientData.Bytes()
}

func (h *tcpReader) ServerStream() []byte {
	h.parent.Lock()
	defer h.parent.Unlock()
	return h.serviceBanner.Bytes()
}

func (h *tcpReader) ConversationRaw() []byte {
	h.parent.Lock()
	defer h.parent.Unlock()
	return h.parent.conversationRaw.Bytes()
}

func (h *tcpReader) ConversationColored() []byte {
	h.parent.Lock()
	defer h.parent.Unlock()
	return h.parent.conversationColored.Bytes()
}

func (h *tcpReader) IsClient() bool {
	return h.isClient
}

func (h *tcpReader) Ident() string {
	return h.parent.ident
}
func (h *tcpReader) Network() gopacket.Flow {
	return h.parent.net
}
func (h *tcpReader) Transport() gopacket.Flow {
	return h.parent.transport
}
func (h *tcpReader) FirstPacket() time.Time {
	return h.parent.firstPacket
}

func (h *tcpReader) Saved() bool {
	return h.saved
}
