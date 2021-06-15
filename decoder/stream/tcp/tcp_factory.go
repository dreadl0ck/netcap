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

package tcp

import (
	"sync"

	"github.com/dreadl0ck/gopacket"
	"github.com/dreadl0ck/gopacket/ip4defrag"
	"go.uber.org/zap"

	"github.com/dreadl0ck/netcap/reassembly"
	"github.com/dreadl0ck/netcap/utils"
)

// StreamFactory is a structure that manages TCP stream reassembly
var StreamFactory = newStreamFactory()

func newStreamFactory() *connectionFactory {
	f := &connectionFactory{
		defragger:  ip4defrag.NewIPv4Defragmenter(),
		FSMOptions: reassembly.TCPSimpleFSMOptions{},
	}
	f.StreamPool = reassembly.NewStreamPool(f)

	return f
}

// GetStreamPool returns the stream pool.
func GetStreamPool() *reassembly.StreamPool {
	return StreamFactory.StreamPool
}

/*
 * The TCP factory: returns a new Connection
 */

// TCPConnectionFactory internal data structure to handle new network streams
// and spawn the stream decoder routines for processing the data.
type connectionFactory struct {
	sync.Mutex
	streamReaders []streamReader
	numActive     int64
	defragger     *ip4defrag.IPv4Defragmenter
	StreamPool    *reassembly.StreamPool
	wg            sync.WaitGroup
	FSMOptions    reassembly.TCPSimpleFSMOptions
}

// New handles a new stream received from the assembler
// this is the entry point for new network streams
// a dedicated stream reader instance will be started and subsequently fed with new data from the stream.
func (factory *connectionFactory) New(net, transport gopacket.Flow, ac reassembly.AssemblerContext) reassembly.Stream {
	reassemblyLog.Debug("new stream",
		zap.String("net", net.String()),
		zap.String("transport", transport.String()),
	)

	// parent structure for tracking the bidirectional connection
	str := &tcpConnection{
		net:         net,
		transport:   transport,
		tcpstate:    reassembly.NewTCPSimpleFSM(factory.FSMOptions),
		ident:       utils.CreateFlowIdentFromLayerFlows(net, transport),
		optchecker:  reassembly.NewTCPOptionCheck(),
		firstPacket: ac.GetCaptureInfo().Timestamp,
	}

	str.decoder = &tcpReader{
		parent: str,
	}
	str.client = str.newTCPStreamReader(true)
	str.server = str.newTCPStreamReader(false)

	factory.wg.Add(2)

	factory.Lock()
	factory.streamReaders = append(
		factory.streamReaders,
		str.client,
		str.server,
	)
	factory.numActive += 2
	factory.Unlock()

	// launch stream readers
	go str.client.Run(factory)
	go str.server.Run(factory)

	return str
}

// waitGoRoutines waits until the goroutines launched to process TCP streams are done
// this will block forever if there are streams that are never shutdown (via RST or FIN flags).
func (factory *connectionFactory) waitGoRoutines() {
	factory.Lock()
	reassemblyLog.Info("waiting for last TCP streams to process", zap.Int64("num", factory.numActive))
	factory.Unlock()

	factory.wg.Wait()
}

// context is the assembler context.
type context struct {
	CaptureInfo gopacket.CaptureInfo
}

// GetCaptureInfo returns the gopacket.CaptureInfo from the context.
func (c *context) GetCaptureInfo() gopacket.CaptureInfo {
	return c.CaptureInfo
}
