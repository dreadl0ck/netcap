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
	decodeSSH     bool
	numActive     int64
	streamReaders []StreamReader
	sync.Mutex
}

// New handles a new stream received from the assembler
// this is the entry point for new network streams
// depending on the used ports, a dedicated stream reader instance will be started and subsequently fed with new data from the stream
func (factory *tcpConnectionFactory) New(net, transport gopacket.Flow, tcp *layers.TCP, ac reassembly.AssemblerContext) reassembly.Stream {

	logReassemblyDebug("* NEW: %s %s\n", net, transport)

	stream := &tcpConnection{
		net:         net,
		transport:   transport,
		//isHTTPS:     tcp.SrcPort == 443 || tcp.DstPort == 443,
		tcpstate:    reassembly.NewTCPSimpleFSM(fsmOptions),
		ident:       filepath.Clean(fmt.Sprintf("%s-%s", net, transport)),
		optchecker:  reassembly.NewTCPOptionCheck(),
		firstPacket: ac.GetCaptureInfo().Timestamp,
	}

	// do not write encrypted HTTP streams to disk for now
	//if stream.isHTTPS {
	//	return stream
	//}

	stream.decoder = &tcpReader{
		parent: stream,
	}
	stream.client = stream.newTCPStreamReader(true)
	stream.server = stream.newTCPStreamReader(false)

	factory.wg.Add(2)

	factory.Lock()
	factory.streamReaders = append(factory.streamReaders, stream.client)
	factory.streamReaders = append(factory.streamReaders, stream.client)
	factory.numActive += 2
	factory.Unlock()

	// launch stream readers
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
