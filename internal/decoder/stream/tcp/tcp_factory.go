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
	"github.com/dreadl0ck/netcap/internal/decoder/core"
	"strconv"
	"sync"

	"github.com/gopacket/gopacket"
	"go.uber.org/zap"

	"github.com/dreadl0ck/netcap/internal/packetview"
	"github.com/dreadl0ck/netcap/internal/reassembly"
	"github.com/dreadl0ck/netcap/internal/utils"
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

	pending := StreamFactory.readerSnapshot()

	for _, reader := range pending {
		if reader != nil {
			reader.CloseData()
		}
	}

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
	streamReaders        []streamReader
	numActive            int64
	StreamPool           *reassembly.StreamPool
	wg                   sync.WaitGroup
	FSMOptions           reassembly.TCPSimpleFSMOptions
	freeReaderSlots      []int
	payloadBudget        *retainedPayloadBudget
	stateBudget          *core.StateBudget
	stateError           error
	stateCancel          func()
	incrementalStreams   uint64
	incrementalCompleted uint64
	incrementalGapResets uint64
	completionOnly       map[string]uint64
	deferredTails        uint64
}

// New handles a new stream received from the assembler
// this is the entry point for new network streams
// a dedicated stream reader instance will be started and subsequently fed with new data from the stream.
func (factory *connectionFactory) New(net, transport gopacket.Flow, ac reassembly.AssemblerContext) reassembly.Stream {
	factory.Lock()
	budget := factory.stateBudget
	factory.Unlock()
	credit := int64(4096)
	if err := budget.Reserve(credit); err != nil {
		factory.failIncremental(err)
		return refusedConnection{}
	}
	reassemblyLog.Debug("new stream",
		zap.String("net", net.String()),
		zap.String("transport", transport.String()),
	)

	// parent structure for tracking the bidirectional connection
	str := &tcpConnection{
		stateBudget: budget,
		stateCredit: credit,
		factory:     factory,
		net:         net,
		transport:   transport,
		tcpstate:    reassembly.NewTCPSimpleFSM(factory.FSMOptions),
		ident:       utils.CreateFlowIdentFromLayerFlows(net, transport),
		optchecker:  reassembly.NewTCPOptionCheck(),
		firstPacket: ac.GetCaptureInfo().Timestamp,
	}
	str.networkScope = "if:" + strconv.Itoa(ac.GetCaptureInfo().InterfaceIndex)
	if c := packetview.FromCapture(ac.GetCaptureInfo()); c != nil {
		str.networkScope = c.Scope
	}
	if c, ok := ac.(*context); ok && c.scope != "" {
		str.networkScope = c.scope
	}

	str.decoder = &tcpReader{
		parent: str,
	}
	client, server := str.newTCPStreamReader(true), str.newTCPStreamReader(false)
	str.client, str.server = client, server

	factory.wg.Add(2)
	client.synchronousFactory, server.synchronousFactory = factory, factory

	factory.Lock()
	str.payloadBudget = factory.payloadBudget
	for _, reader := range []*tcpStreamReader{client, server} {
		slot := len(factory.streamReaders)
		if last := len(factory.freeReaderSlots) - 1; last >= 0 {
			slot = factory.freeReaderSlots[last]
			factory.freeReaderSlots = factory.freeReaderSlots[:last]
		} else {
			factory.streamReaders = append(factory.streamReaders, nil)
		}
		factory.streamReaders[slot] = reader
		reader.factorySlot = slot
	}
	factory.numActive += 2
	factory.Unlock()

	// StoreData owns each delivery synchronously; no drain-only goroutine or
	// per-direction buffered channel is needed for production readers.

	return str
}

// context is the assembler context.
type context struct {
	CaptureInfo gopacket.CaptureInfo
	link        gopacket.Flow
	scope       string
}

func (c *context) GetLinkFlow() gopacket.Flow { return c.link }

// GetCaptureInfo returns the gopacket.CaptureInfo from the context.
func (c *context) GetCaptureInfo() gopacket.CaptureInfo {
	return c.CaptureInfo
}
