/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package tcp

import (
	"sync"

	"github.com/gopacket/gopacket"
	"go.uber.org/zap"

	"github.com/dreadl0ck/netcap/reassembly"
	"github.com/dreadl0ck/netcap/utils"
)

// StreamFactory is a structure that manages TCP stream reassembly
var StreamFactory = newStreamFactory()

func newStreamFactory() *connectionFactory {
	return &connectionFactory{
		FSMOptions: reassembly.TCPSimpleFSMOptions{},
	}
}

// CloseStreamReaderChannelsAndWait closes all TCP stream reader channels and waits for goroutines to finish.
// Call only after packet workers join and every assembler has been flushed.
// This MUST be called BEFORE closing log files to avoid write errors.
// CRITICAL: Each TCP connection spawns 2 goroutines (client + server) that run tcpStreamReader.Run()
// These goroutines must be properly shut down before log files are closed.
func CloseStreamReaderChannelsAndWait() {
	closeStreamReaderChannelsAndWaitInternal(true)
}

// CloseStreamReaderChannelsAndWaitQuiet is like CloseStreamReaderChannelsAndWait but doesn't log.
// Use this when log files may already be closed (e.g., between multi-file processing).
func CloseStreamReaderChannelsAndWaitQuiet() {
	closeStreamReaderChannelsAndWaitInternal(false)
}

// closeStreamReaderChannelsAndWaitInternal implements the actual cleanup logic.
func closeStreamReaderChannelsAndWaitInternal(doLog bool) {
	if StreamFactory == nil {
		return
	}

	// Close each reader's dataChan exactly once to signal EOF.
	// A watermark rather than a flag: readers registered by a later capture
	// still need closing, otherwise the wait below never returns.
	StreamFactory.Lock()
	pending := StreamFactory.streamReaders[StreamFactory.closedReaders:]
	StreamFactory.closedReaders = len(StreamFactory.streamReaders)
	StreamFactory.Unlock()

	for _, reader := range pending {
		if reader != nil && reader.DataChan() != nil {
			close(reader.DataChan())
		}
	}

	// Now wait for all goroutines to finish
	// This will block until all tcpStreamReader.Run() goroutines have exited
	// and called Cleanup() which does wg.Done()
	if doLog {
		StreamFactory.Lock()
		reassemblyLog.Info("waiting for last TCP streams to process", zap.Int64("num", StreamFactory.numActive))
		StreamFactory.Unlock()
	}
	StreamFactory.wg.Wait()
}

// ResetStreamFactory clears state between captures, after all workers and readers join.
func ResetStreamFactory() {
	if StreamFactory != nil {
		if StreamFactory.StreamPool != nil {
			StreamFactory.StreamPool.Reset()
			StreamFactory.StreamPool = nil
		}
		StreamFactory = nil
	}

	StreamFactory = newStreamFactory()
}

// GetStreamPool returns the stream pool.
func GetStreamPool() *reassembly.StreamPool {
	StreamFactory.Lock()
	defer StreamFactory.Unlock()
	// Legacy callers share a pool; worker-owned pools do not retain this cache.
	if StreamFactory.StreamPool == nil {
		StreamFactory.StreamPool = reassembly.NewStreamPool(StreamFactory)
	}
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
	StreamPool    *reassembly.StreamPool
	wg            sync.WaitGroup
	FSMOptions    reassembly.TCPSimpleFSMOptions
	closedReaders int
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

// context is the assembler context.
type context struct {
	CaptureInfo gopacket.CaptureInfo
}

// GetCaptureInfo returns the gopacket.CaptureInfo from the context.
func (c *context) GetCaptureInfo() gopacket.CaptureInfo {
	return c.CaptureInfo
}
