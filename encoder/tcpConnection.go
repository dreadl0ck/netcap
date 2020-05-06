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

// This code is based on the gopacket/examples/reassemblydump/main.go example.
// The following license is provided:
// Copyright (c) 2012 Google, Inc. All rights reserved.
// Copyright (c) 2009-2011 Andreas Krennmair. All rights reserved.

// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:

//    * Redistributions of source code must retain the above copyright
// notice, this list of conditions and the following disclaimer.
//    * Redistributions in binary form must reproduce the above
// copyright notice, this list of conditions and the following disclaimer
// in the documentation and/or other materials provided with the
// distribution.
//    * Neither the name of Andreas Krennmair, Google, nor the names of its
// contributors may be used to endorse or promote products derived from
// this software without specific prior written permission.

// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

package encoder

import (
	"encoding/hex"
	"fmt"
	"github.com/davecgh/go-spew/spew"
	"github.com/dreadl0ck/netcap"
	"github.com/dreadl0ck/netcap/utils"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"runtime/pprof"
	"strconv"
	"sync"
	"time"

	"github.com/dreadl0ck/gopacket/ip4defrag"
	"github.com/evilsocket/islazy/tui"

	"github.com/dreadl0ck/netcap/types"

	"github.com/dreadl0ck/gopacket"
	"github.com/dreadl0ck/gopacket/layers"
	"github.com/dreadl0ck/netcap/reassembly"
)

var (
	defragger     = ip4defrag.NewIPv4Defragmenter()
	streamFactory = &tcpConnectionFactory{}
	StreamPool    = reassembly.NewStreamPool(streamFactory)
	numErrors     uint

	requests  = 0
	responses = 0
	// synchronizes access to stats
	statsMutex sync.Mutex

	count          = 0
	dataBytes      = int64(0)
	start          = time.Now()
	errorsMap      = make(map[string]uint)
	errorsMapMutex sync.Mutex
	fsmOptions     = reassembly.TCPSimpleFSMOptions{}
)

var reassemblyStats struct {
	ipdefrag            int64
	missedBytes         int64
	pkt                 int64
	sz                  int64
	totalsz             int64
	rejectFsm           int64
	rejectOpt           int64
	rejectConnFsm       int64
	reassembled         int64
	outOfOrderBytes     int64
	outOfOrderPackets   int64
	biggestChunkBytes   int64
	biggestChunkPackets int64
	overlapBytes        int64
	overlapPackets      int64
	savedStreams        int64
	numSoftware         int64
	numServices         int64
}

func NumSavedStreams() int64 {
	statsMutex.Lock()
	defer statsMutex.Unlock()
	return reassemblyStats.savedStreams
}

/*
 * The TCP factory: returns a new Connection
 */

type tcpConnectionFactory struct {
	wg         sync.WaitGroup
	decodeHTTP bool
	decodePOP3 bool
	numActive  int64
	sync.Mutex
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
			bytes:    make(chan []byte, 100),
			ident:    filepath.Clean(fmt.Sprintf("%s-%s", net, transport)),
			hexdump:  c.HexDump,
			parent:   stream,
			isClient: true,
		}
		stream.server = &httpReader{
			bytes:   make(chan []byte, 100),
			ident:   filepath.Clean(fmt.Sprintf("%s-%s", net.Reverse(), transport.Reverse())),
			hexdump: c.HexDump,
			parent:  stream,
		}

		// kickoff decoders for client and server
		factory.wg.Add(2)
		factory.Lock()
		factory.numActive += 2
		factory.Unlock()
		go stream.client.Run(factory)
		go stream.server.Run(factory)

	case stream.isPOP3:
		stream.client = &pop3Reader{
			bytes:    make(chan []byte, 100),
			ident:    filepath.Clean(fmt.Sprintf("%s-%s", net, transport)),
			hexdump:  c.HexDump,
			parent:   stream,
			isClient: true,
		}
		stream.server = &pop3Reader{
			bytes:   make(chan []byte, 100),
			ident:   filepath.Clean(fmt.Sprintf("%s-%s", net.Reverse(), transport.Reverse())),
			hexdump: c.HexDump,
			parent:  stream,
		}

		// kickoff decoders for client and server
		factory.wg.Add(2)
		factory.Lock()
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

		if c.SaveStreams {

			stream.client = &tcpReader{
				bytes:    make(chan []byte, 100),
				ident:    filepath.Clean(fmt.Sprintf("%s-%s", net, transport)),
				hexdump:  c.HexDump,
				parent:   stream,
				isClient: true,
			}
			stream.server = &tcpReader{
				bytes:   make(chan []byte, 100),
				ident:   filepath.Clean(fmt.Sprintf("%s-%s", net.Reverse(), transport.Reverse())),
				hexdump: c.HexDump,
				parent:  stream,
			}

			// kickoff readers for client and server
			factory.wg.Add(2)
			factory.Lock()
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

/*
 * TCP Connection
 */

/* It's a connection (bidirectional) */
type tcpConnection struct {
	tcpstate   *reassembly.TCPSimpleFSM
	optchecker reassembly.TCPOptionCheck

	net, transport gopacket.Flow

	fsmerr   bool
	isHTTP   bool
	isPOP3   bool
	isHTTPS  bool
	reversed bool
	ident    string

	client ConnectionReader
	server ConnectionReader

	firstPacket time.Time

	requests  []*httpRequest
	responses []*httpResponse

	pop3Requests  []*types.POP3Request
	pop3Responses []*types.POP3Response

	// if set, indicates that either client or server http reader was closed already
	last bool

	sync.Mutex
}

type httpRequest struct {
	request   *http.Request
	timestamp string
	clientIP  string
	serverIP  string
}

type httpResponse struct {
	response  *http.Response
	timestamp string
	clientIP  string
	serverIP  string
}

func (t *tcpConnection) Accept(tcp *layers.TCP, ci gopacket.CaptureInfo, dir reassembly.TCPFlowDirection, nextSeq reassembly.Sequence, start *bool, ac reassembly.AssemblerContext) bool {
	// FSM
	if !t.tcpstate.CheckState(tcp, dir) {
		logReassemblyError("FSM", "%s: Packet rejected by FSM (state:%s)\n", t.ident, t.tcpstate.String())
		statsMutex.Lock()
		reassemblyStats.rejectFsm++
		if !t.fsmerr {
			t.fsmerr = true
			reassemblyStats.rejectConnFsm++
		}
		statsMutex.Unlock()
		if !c.IgnoreFSMerr {
			return false
		}
	}
	// Options
	err := t.optchecker.Accept(tcp, ci, dir, nextSeq, start)
	if err != nil {
		logReassemblyError("OptionChecker", "%s: Packet rejected by OptionChecker: %s\n", t.ident, err)
		statsMutex.Lock()
		reassemblyStats.rejectOpt++
		statsMutex.Unlock()
		if !c.NoOptCheck {
			return false
		}
	}
	// Checksum
	accept := true
	if c.Checksum {
		c, err := tcp.ComputeChecksum()
		if err != nil {
			logReassemblyError("ChecksumCompute", "%s: Got error computing checksum: %s\n", t.ident, err)
			accept = false
		} else if c != 0x0 {
			logReassemblyError("Checksum", "%s: Invalid checksum: 0x%x\n", t.ident, c)
			accept = false
		}
	}
	if !accept {
		statsMutex.Lock()
		reassemblyStats.rejectOpt++
		statsMutex.Unlock()
	}
	return accept
}

func (t *tcpConnection) updateStats(sg reassembly.ScatterGather, skip int, length int, saved int, start bool, end bool, dir reassembly.TCPFlowDirection) {

	sgStats := sg.Stats()

	statsMutex.Lock()
	if skip > 0 {
		reassemblyStats.missedBytes += int64(skip)
	}

	reassemblyStats.sz += int64(length - saved)
	reassemblyStats.pkt += int64(sgStats.Packets)
	if sgStats.Chunks > 1 {
		reassemblyStats.reassembled++
	}
	reassemblyStats.outOfOrderPackets += int64(sgStats.QueuedPackets)
	reassemblyStats.outOfOrderBytes += int64(sgStats.QueuedBytes)
	if int64(length) > reassemblyStats.biggestChunkBytes {
		reassemblyStats.biggestChunkBytes = int64(length)
	}
	if int64(sgStats.Packets) > reassemblyStats.biggestChunkPackets {
		reassemblyStats.biggestChunkPackets = int64(sgStats.Packets)
	}
	if sgStats.OverlapBytes != 0 && sgStats.OverlapPackets == 0 {
		utils.ReassemblyLog.Println("ReassembledSG: invalid overlap, bytes:", sgStats.OverlapBytes, "packets:", sgStats.OverlapPackets)
	}
	reassemblyStats.overlapBytes += int64(sgStats.OverlapBytes)
	reassemblyStats.overlapPackets += int64(sgStats.OverlapPackets)
	statsMutex.Unlock()

	var ident string
	if dir == reassembly.TCPDirClientToServer {
		ident = fmt.Sprintf("%v %v(%s): ", t.net, t.transport, dir)
	} else {
		ident = fmt.Sprintf("%v %v(%s): ", t.net.Reverse(), t.transport.Reverse(), dir)
	}

	logReassemblyDebug("%s: SG reassembled packet with %d bytes (start:%v,end:%v,skip:%d,saved:%d,nb:%d,%d,overlap:%d,%d)\n", ident, length, start, end, skip, saved, sgStats.Packets, sgStats.Chunks, sgStats.OverlapBytes, sgStats.OverlapPackets)
}

// TODO: feed data into intermediary buffer, so this operation is non blocking and does not need an extra goroutine?
func (t *tcpConnection) feedData(dir reassembly.TCPFlowDirection, data []byte) {
	if dir == reassembly.TCPDirClientToServer && !t.reversed {
		t.client.BytesChan() <- data
	} else {
		t.server.BytesChan() <- data
	}
}

func (t *tcpConnection) feedDataTimeout(dir reassembly.TCPFlowDirection, data []byte) {
	if dir == reassembly.TCPDirClientToServer && !t.reversed {
		select {
		case t.client.BytesChan() <- data:
		case <-time.After(100 * time.Millisecond):
			//fmt.Println(t.ident, "timeout")
		}
	} else {
		select {
		case t.server.BytesChan() <- data:
		case <-time.After(100 * time.Millisecond):
			//fmt.Println(t.ident, "timeout")
		}
	}
}

func (t *tcpConnection) ReassembledSG(sg reassembly.ScatterGather, ac reassembly.AssemblerContext) {

	length, saved := sg.Lengths()
	dir, start, end, skip := sg.Info()

	// update stats
	t.updateStats(sg, skip, length, saved, start, end, dir)

	if skip == -1 && c.AllowMissingInit {
		// this is allowed
	} else if skip != 0 {
		// Missing bytes in stream: do not even try to parse it
		return
	}

	data := sg.Fetch(length)
	switch {
	case t.isHTTP:
		if length > 0 {
			if c.HexDump {
				logReassemblyDebug("Feeding http with:\n%s", hex.Dump(data))
			}
			t.feedData(dir, data)
		}
	case t.isPOP3:
		if length > 0 {
			if c.HexDump {
				logReassemblyDebug("Feeding POP3 with:\n%s", hex.Dump(data))
			}
			t.feedData(dir, data)
		}
	default:

		// do not process encrypted HTTP streams for now
		if t.isHTTPS {
			return
		}

		if c.SaveStreams {
			if length > 0 {
				if c.HexDump {
					logReassemblyDebug("Feeding TCP stream reader with:\n%s", hex.Dump(data))
				}
				t.feedData(dir, data)
			}
		}
	}
}

func (t *tcpConnection) ReassemblyComplete(ac reassembly.AssemblerContext) bool {
	logReassemblyDebug("%s: Connection closed\n", t.ident)
	if t.isHTTP {
		// closing here causes a panic sometimes because the channel is already closed
		// as a temporary bugfix, closing the channels was omitted.
		// channels don't have to be closed.
		// they will be garbage collected if no goroutines reference them any more

		// fmt.Println("close", t.ident, "client")
		// close(t.client.bytes)
		// fmt.Println("close", t.ident, "server")
		// close(t.server.bytes)

		// in case one is already closed there will be a panic
		// we need to recover from that and do the same for the server
		// by using two anonymous functions this is possible
		// I created a snippet to verify: https://goplay.space/#m8-zwTuGrgS
		func() {
			defer recovery()
			close(t.client.BytesChan())
		}()
		func() {
			defer recovery()
			close(t.server.BytesChan())
		}()
	}
	// do not remove the connection to allow last ACK
	return false
}

func ReassemblePacket(packet gopacket.Packet, assembler *reassembly.Assembler) {

	// prevent passing any non TCP packets in here
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return
	}

	data := packet.Data()

	// lock to sync with read on destroy
	errorsMapMutex.Lock()
	count++
	dataBytes += int64(len(data))
	errorsMapMutex.Unlock()

	// defrag the IPv4 packet if required
	if !c.NoDefrag {
		ip4Layer := packet.Layer(layers.LayerTypeIPv4)
		if ip4Layer == nil {
			return
		}

		var (
			ip4         = ip4Layer.(*layers.IPv4)
			l           = ip4.Length
			newip4, err = defragger.DefragIPv4(ip4)
		)
		if err != nil {
			log.Fatalln("Error while de-fragmenting", err)
		} else if newip4 == nil {
			logReassemblyDebug("Fragment...\n")
			return
		}
		if newip4.Length != l {
			reassemblyStats.ipdefrag++
			logReassemblyDebug("Decoding re-assembled packet: %s\n", newip4.NextLayerType())
			pb, ok := packet.(gopacket.PacketBuilder)
			if !ok {
				panic("Not a PacketBuilder")
			}
			nextDecoder := newip4.NextLayerType()
			if err := nextDecoder.Decode(newip4.Payload, pb); err != nil {
				fmt.Println("failed to decode ipv4:", err)
			}
		}
	}

	tcp := tcpLayer.(*layers.TCP)
	if c.Checksum {
		err := tcp.SetNetworkLayerForChecksum(packet.NetworkLayer())
		if err != nil {
			log.Fatalf("Failed to set network layer for checksum: %s\n", err)
		}
	}
	statsMutex.Lock()
	reassemblyStats.totalsz += int64(len(tcp.Payload))
	statsMutex.Unlock()

	// for debugging:
	//AssembleWithContextTimeout(packet, assembler, tcp)

	assembler.AssembleWithContext(packet.NetworkLayer().NetworkFlow(), tcp, &Context{
		CaptureInfo: packet.Metadata().CaptureInfo,
	})

	// flush connections in interval
	if count%c.FlushEvery == 0 {
		ref := packet.Metadata().CaptureInfo.Timestamp
		flushed, closed := assembler.FlushWithOptions(reassembly.FlushOptions{T: ref.Add(-c.ClosePendingTimeOut), TC: ref.Add(-c.CloseInactiveTimeOut)})

		utils.DebugLog.Printf("Forced flush: %d flushed, %d closed (%s)\n", flushed, closed, ref)
	}
}

// AssembleWithContextTimeout is a function that times out with a log message after a specified interval
// when the stream reassembly gets stuck
// used for debugging
func AssembleWithContextTimeout(packet gopacket.Packet, assembler *reassembly.Assembler, tcp *layers.TCP) {

	done := make(chan bool, 1)
	go func() {
		assembler.AssembleWithContext(packet.NetworkLayer().NetworkFlow(), tcp, &Context{
			CaptureInfo: packet.Metadata().CaptureInfo,
		})
		done <- true
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		spew.Dump(packet.Metadata().CaptureInfo)
		fmt.Println("HTTP AssembleWithContext timeout", packet.NetworkLayer().NetworkFlow(), packet.TransportLayer().TransportFlow())
		fmt.Println(assembler.Dump())
	}
}

func CleanupReassembly(wait bool) {

	cMu.Lock()
	if c.Debug {
		utils.ReassemblyLog.Println("StreamPool:")
		utils.ReassemblyLog.Println(StreamPool.DumpString())
	}
	cMu.Unlock()

	// wait for stream reassembly to finish
	if c.WaitForConnections || wait {
		if !Quiet {
			fmt.Print("waiting for last streams to finish processing...")
		}
		select {
		case <-waitForConns():
			if !Quiet {
				fmt.Println(" done!")
			}
		case <-time.After(netcap.DefaultReassemblyTimeout):
			if !Quiet {
				fmt.Println(" timeout after", netcap.DefaultReassemblyTimeout)
			}
		}
	}

	// create a memory snapshot for debugging
	if c.MemProfile != "" {
		f, err := os.Create(c.MemProfile)
		if err != nil {
			log.Fatal(err)
		}
		if err := pprof.WriteHeapProfile(f); err != nil {
			log.Fatal("failed to write heap profile:", err)
		}
		if err := f.Close(); err != nil {
			log.Fatal("failed to close heap profile file:", err)
		}
	}

	// print stats if not quiet
	if !Quiet {
		errorsMapMutex.Lock()
		utils.ReassemblyLog.Printf("HTTPEncoder: Processed %v packets (%v bytes) in %v (errors: %v, type:%v)\n", count, dataBytes, time.Since(start), numErrors, len(errorsMap))
		errorsMapMutex.Unlock()

		// print configuration
		// print configuration as table
		tui.Table(utils.ReassemblyLogFileHandle, []string{"Reassembly Setting", "Value"}, [][]string{
			{"FlushEvery", strconv.Itoa(c.FlushEvery)},
			{"CloseInactiveTimeout", c.CloseInactiveTimeOut.String()},
			{"ClosePendingTimeout", c.ClosePendingTimeOut.String()},
			{"AllowMissingInit", strconv.FormatBool(c.AllowMissingInit)},
			{"IgnoreFsmErr", strconv.FormatBool(c.IgnoreFSMerr)},
			{"NoOptCheck", strconv.FormatBool(c.NoOptCheck)},
			{"Checksum", strconv.FormatBool(c.Checksum)},
			{"NoDefrag", strconv.FormatBool(c.NoDefrag)},
			{"WriteIncomplete", strconv.FormatBool(c.WriteIncomplete)},
		})

		printProgress(1, 1)

		statsMutex.Lock()
		rows := [][]string{}
		if !c.NoDefrag {
			rows = append(rows, []string{"IPdefrag", strconv.FormatInt(reassemblyStats.ipdefrag, 10)})
		}
		rows = append(rows, []string{"missed bytes", strconv.FormatInt(reassemblyStats.missedBytes, 10)})
		rows = append(rows, []string{"total packets", strconv.FormatInt(reassemblyStats.pkt, 10)})
		rows = append(rows, []string{"rejected FSM", strconv.FormatInt(reassemblyStats.rejectFsm, 10)})
		rows = append(rows, []string{"rejected Options", strconv.FormatInt(reassemblyStats.rejectOpt, 10)})
		rows = append(rows, []string{"reassembled bytes", strconv.FormatInt(reassemblyStats.sz, 10)})
		rows = append(rows, []string{"total TCP bytes", strconv.FormatInt(reassemblyStats.totalsz, 10)})
		rows = append(rows, []string{"conn rejected FSM", strconv.FormatInt(reassemblyStats.rejectConnFsm, 10)})
		rows = append(rows, []string{"reassembled chunks", strconv.FormatInt(reassemblyStats.reassembled, 10)})
		rows = append(rows, []string{"out-of-order packets", strconv.FormatInt(reassemblyStats.outOfOrderPackets, 10)})
		rows = append(rows, []string{"out-of-order bytes", strconv.FormatInt(reassemblyStats.outOfOrderBytes, 10)})
		rows = append(rows, []string{"biggest-chunk packets", strconv.FormatInt(reassemblyStats.biggestChunkPackets, 10)})
		rows = append(rows, []string{"biggest-chunk bytes", strconv.FormatInt(reassemblyStats.biggestChunkBytes, 10)})
		rows = append(rows, []string{"overlap packets", strconv.FormatInt(reassemblyStats.overlapPackets, 10)})
		rows = append(rows, []string{"overlap bytes", strconv.FormatInt(reassemblyStats.overlapBytes, 10)})
		rows = append(rows, []string{"saved streams", strconv.FormatInt(reassemblyStats.savedStreams, 10)})
		rows = append(rows, []string{"numSoftware", strconv.FormatInt(reassemblyStats.numSoftware, 10)})
		rows = append(rows, []string{"numServices", strconv.FormatInt(reassemblyStats.numServices, 10)})
		statsMutex.Unlock()

		tui.Table(utils.ReassemblyLogFileHandle, []string{"TCP Stat", "Value"}, rows)

		errorsMapMutex.Lock()
		statsMutex.Lock()
		if numErrors != 0 {
			rows = [][]string{}
			for e := range errorsMap {
				rows = append(rows, []string{e, strconv.FormatUint(uint64(errorsMap[e]), 10)})
			}
			tui.Table(utils.ReassemblyLogFileHandle, []string{"Error Subject", "Count"}, rows)
		}
		utils.ReassemblyLog.Println("\nencountered", numErrors, "errors during processing.", "HTTP requests", requests, " responses", responses)
		statsMutex.Unlock()
		errorsMapMutex.Unlock()
	}
}

func waitForConns() chan struct{} {
	out := make(chan struct{})

	go func() {
		streamFactory.WaitGoRoutines()
		out <- struct{}{}
	}()

	return out
}
