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
	deadlock "github.com/sasha-s/go-deadlock"
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
	deadlock.Mutex
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
	SetClient(bool)
	Ident() string
	Network() gopacket.Flow
	Transport() gopacket.Flow
	FirstPacket() time.Time
	Saved() bool
	NumBytes() int
	Client() StreamReader
	ServiceBanner() []byte
	MarkSaved()
}

// New handles a new stream received from the assembler
// this is the entry point for new network streams
// depending on the used ports, a dedicated stream reader instance will be started and subsequently fed with new data from the stream
// TODO: add logic to identify protocol and update the used decoder after we saw some traffic from the connection
func (factory *tcpConnectionFactory) New(net, transport gopacket.Flow, tcp *layers.TCP, ac reassembly.AssemblerContext) reassembly.Stream {

	logReassemblyDebug("* NEW: %s %s\n", net, transport)

	stream := &tcpConnection{
		net:         net,
		transport:   transport,
		isHTTP:      factory.decodeHTTP && (tcp.SrcPort == 80 || tcp.DstPort == 80),
		isPOP3:      factory.decodePOP3 && (tcp.SrcPort == 110 || tcp.DstPort == 110),
		isHTTPS:     tcp.SrcPort == 443 || tcp.DstPort == 443,
		isSSH:       tcp.SrcPort == 22 || tcp.DstPort == 22,
		tcpstate:    reassembly.NewTCPSimpleFSM(fsmOptions),
		ident:       filepath.Clean(fmt.Sprintf("%s-%s", net, transport)),
		optchecker:  reassembly.NewTCPOptionCheck(),
		firstPacket: ac.GetCaptureInfo().Timestamp,
	}

	clientIdent := filepath.Clean(fmt.Sprintf("%s-%s", net, transport))
	serverIdent := filepath.Clean(fmt.Sprintf("%s-%s", net, transport))

	// do not write encrypted HTTP streams to disk for now
	if stream.isHTTPS {
		// don't capture encrypted HTTPS traffic
		return stream
	}

	switch {
	case stream.isHTTP:

		// handle out of order packets
		if tcp.DstPort != 80 {
			clientIdent = filepath.Clean(fmt.Sprintf("%s-%s", net.Reverse(), transport.Reverse()))
			serverIdent = filepath.Clean(fmt.Sprintf("%s-%s", net, transport))
		}

		stream.client = &httpReader{
			dataChan:    make(chan *Data, c.StreamDecoderBufSize),
			ident:    clientIdent,
			hexdump:  c.HexDump,
			parent:   stream,
			isClient: true,
		}
		stream.server = &httpReader{
			dataChan:    make(chan *Data, c.StreamDecoderBufSize),
			ident:   serverIdent,
			hexdump: c.HexDump,
			parent:  stream,
		}

	case stream.isSSH:

		// handle out of order packets
		if tcp.DstPort != 22 {
			clientIdent = filepath.Clean(fmt.Sprintf("%s-%s", net.Reverse(), transport.Reverse()))
			serverIdent = filepath.Clean(fmt.Sprintf("%s-%s", net, transport))
		}

		stream.client = &sshReader{
			dataChan:    make(chan *Data, c.StreamDecoderBufSize),
			ident:    clientIdent,
			hexdump:  c.HexDump,
			parent:   stream,
			isClient: true,
		}
		stream.server = &sshReader{
			dataChan:    make(chan *Data, c.StreamDecoderBufSize),
			ident:   serverIdent,
			hexdump: c.HexDump,
			parent:  stream,
		}

	case stream.isPOP3:

		// handle out of order packets
		if tcp.DstPort != 110 {
			clientIdent = filepath.Clean(fmt.Sprintf("%s-%s", net.Reverse(), transport.Reverse()))
			serverIdent = filepath.Clean(fmt.Sprintf("%s-%s", net, transport))
		}

		stream.client = &pop3Reader{
			dataChan:     make(chan *Data, c.StreamDecoderBufSize),
			ident:    filepath.Clean(fmt.Sprintf("%s-%s", net, transport)),
			hexdump:  c.HexDump,
			parent:   stream,
			isClient: true,
		}
		stream.server = &pop3Reader{
			dataChan:     make(chan *Data, c.StreamDecoderBufSize),
			ident:   filepath.Clean(fmt.Sprintf("%s-%s", net.Reverse(), transport.Reverse())),
			hexdump: c.HexDump,
			parent:  stream,
		}

	default: // process unknown TCP stream
		stream.client = &tcpReader{
			dataChan: make(chan *Data, c.StreamDecoderBufSize),
			ident:    filepath.Clean(fmt.Sprintf("%s-%s", net, transport)),
			hexdump:  c.HexDump,
			parent:   stream,
			isClient: true,
		}
		stream.server = &tcpReader{
			dataChan: make(chan *Data, c.StreamDecoderBufSize),
			ident:    filepath.Clean(fmt.Sprintf("%s-%s", net.Reverse(), transport.Reverse())),
			hexdump:  c.HexDump,
			parent:   stream,
		}
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

	return stream
}

// WaitGoRoutines waits until the goroutines launched to process TCP streams are done
// this will block forever if there are streams that are never shutdown (via RST or FIN flags)
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
