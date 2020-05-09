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
	"fmt"
	"github.com/dreadl0ck/gopacket"
	"github.com/dreadl0ck/gopacket/ip4defrag"
	"github.com/dreadl0ck/gopacket/layers"
	"github.com/dreadl0ck/netcap/reassembly"
	"path/filepath"
	"sync"
	"time"
)

var (
	defragger     = ip4defrag.NewIPv4Defragmenter()
	streamFactory = &tcpConnectionFactory{}
	StreamPool    = reassembly.NewStreamPool(streamFactory)
	fsmOptions    = reassembly.TCPSimpleFSMOptions{}
)

/*
 * The TCP factory: returns a new Connection
 */

// internal data structure to handle new network streams
// and spawn the stream decoder routines for processing the data
type tcpConnectionFactory struct {
	wg            sync.WaitGroup
	decodeHTTP    bool
	decodePOP3    bool
	numActive     int64
	streamReaders []StreamReader
	sync.Mutex
}

// StreamReader is an interface used to describe a processed uni-directional stream
// it is used to close the remaining open streams and process the remaining data
// when the engine is stopped
type StreamReader interface {
	ClientStream() []byte
	ServerStream() []byte
	ConversationRaw() []byte
	ConversationColored() []byte
	IsClient() bool
	Ident() string
	Network() gopacket.Flow
	Transport() gopacket.Flow
	FirstPacket() time.Time
	Saved() bool
}

// New handles a new stream received from the assembler
func (factory *tcpConnectionFactory) New(net, transport gopacket.Flow, tcp *layers.TCP, ac reassembly.AssemblerContext) reassembly.Stream {

	logReassemblyDebug("* NEW: %s %s\n", net, transport)

	stream := &tcpConnection{
		net:         net,
		transport:   transport,
		isHTTP:      factory.decodeHTTP && (tcp.SrcPort == 80 || tcp.DstPort == 80),
		isPOP3:      factory.decodePOP3 && (tcp.SrcPort == 110 || tcp.DstPort == 110),
		isHTTPS:     tcp.SrcPort == 443 || tcp.DstPort == 443,
		reversed:    tcp.SrcPort == 80,
		tcpstate:    reassembly.NewTCPSimpleFSM(fsmOptions),
		ident:       filepath.Clean(fmt.Sprintf("%s-%s", net, transport)),
		optchecker:  reassembly.NewTCPOptionCheck(),
		firstPacket: ac.GetCaptureInfo().Timestamp,
	}

	switch {
	case stream.isHTTP:
		stream.client = &httpReader{
			bytes:    make(chan []byte, c.StreamDecoderBufSize),
			ident:    filepath.Clean(fmt.Sprintf("%s-%s", net, transport)),
			hexdump:  c.HexDump,
			parent:   stream,
			isClient: true,
		}
		stream.server = &httpReader{
			bytes:   make(chan []byte, c.StreamDecoderBufSize),
			ident:   filepath.Clean(fmt.Sprintf("%s-%s", net.Reverse(), transport.Reverse())),
			hexdump: c.HexDump,
			parent:  stream,
		}

		// kickoff decoders for client and server
		factory.wg.Add(2)
		factory.Lock()
		factory.streamReaders = append(factory.streamReaders, stream.client.(StreamReader))
		factory.streamReaders = append(factory.streamReaders, stream.server.(StreamReader))
		factory.numActive += 2
		factory.Unlock()
		go stream.client.Run(factory)
		go stream.server.Run(factory)

	case stream.isPOP3:
		stream.client = &pop3Reader{
			bytes:    make(chan []byte, c.StreamDecoderBufSize),
			ident:    filepath.Clean(fmt.Sprintf("%s-%s", net, transport)),
			hexdump:  c.HexDump,
			parent:   stream,
			isClient: true,
		}
		stream.server = &pop3Reader{
			bytes:   make(chan []byte, c.StreamDecoderBufSize),
			ident:   filepath.Clean(fmt.Sprintf("%s-%s", net.Reverse(), transport.Reverse())),
			hexdump: c.HexDump,
			parent:  stream,
		}

		// kickoff decoders for client and server
		factory.wg.Add(2)
		factory.Lock()
		factory.streamReaders = append(factory.streamReaders, stream.client.(StreamReader))
		factory.streamReaders = append(factory.streamReaders, stream.server.(StreamReader))
		factory.numActive += 2
		factory.Unlock()
		go stream.client.Run(factory)
		go stream.server.Run(factory)
	default:

		// do not write encrypted HTTP streams to disk for now
		if stream.isHTTPS {
			// don't capture encrypted HTTPS traffic
			return stream
		}

		if c.SaveConns {

			stream.client = &tcpReader{
				bytes:    make(chan []byte, c.StreamDecoderBufSize),
				ident:    filepath.Clean(fmt.Sprintf("%s-%s", net, transport)),
				hexdump:  c.HexDump,
				parent:   stream,
				isClient: true,
			}
			stream.server = &tcpReader{
				bytes:   make(chan []byte, c.StreamDecoderBufSize),
				ident:   filepath.Clean(fmt.Sprintf("%s-%s", net.Reverse(), transport.Reverse())),
				hexdump: c.HexDump,
				parent:  stream,
			}

			// kickoff readers for client and server
			factory.wg.Add(2)
			factory.Lock()
			factory.streamReaders = append(factory.streamReaders, stream.client.(StreamReader))
			factory.streamReaders = append(factory.streamReaders, stream.server.(StreamReader))
			factory.numActive += 2
			factory.Unlock()
			go stream.client.Run(factory)
			go stream.server.Run(factory)
		}
	}

	return stream
}

func (factory *tcpConnectionFactory) WaitGoRoutines() {

	if !Quiet {
		factory.Lock()
		fmt.Println("\nwaiting for", factory.numActive, "flows")
		factory.Unlock()
	}

	factory.wg.Wait()
}

// Context is the assembler context
type Context struct {
	CaptureInfo gopacket.CaptureInfo
}

// GetCaptureInfo returns the gopacket.CaptureInfo from the context
func (c *Context) GetCaptureInfo() gopacket.CaptureInfo {
	return c.CaptureInfo
}
