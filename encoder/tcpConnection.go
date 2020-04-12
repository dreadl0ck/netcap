/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) 2017 Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
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
	"github.com/dreadl0ck/gopacket/reassembly"
)

var (
	defragger      = ip4defrag.NewIPv4Defragmenter()
	streamFactory  = &tcpConnectionFactory{}
	StreamPool     = reassembly.NewStreamPool(streamFactory)
	numErrors      uint
	requests       = 0
	responses      = 0
	mu             sync.Mutex
	count          = 0
	dataBytes      = int64(0)
	start          = time.Now()
	errorsMap      = make(map[string]uint)
	errorsMapMutex sync.Mutex
	FileStorage    string
)

var reassemblyStats struct {
	ipdefrag            int
	missedBytes         int
	pkt                 int
	sz                  int
	totalsz             int
	rejectFsm           int
	rejectOpt           int
	rejectConnFsm       int
	reassembled         int
	outOfOrderBytes     int
	outOfOrderPackets   int
	biggestChunkBytes   int
	biggestChunkPackets int
	overlapBytes        int
	overlapPackets      int
}

/*
 * The TCP factory: returns a new Connection
 */

type tcpConnectionFactory struct {
	wg         sync.WaitGroup
	decodeHTTP bool
	decodePOP3 bool
}

var fsmOptions = reassembly.TCPSimpleFSMOptions{}

func (factory *tcpConnectionFactory) New(net, transport gopacket.Flow, tcp *layers.TCP, ac reassembly.AssemblerContext) reassembly.Stream {

	logReassemblyDebug("* NEW: %s %s\n", net, transport)

	stream := &tcpConnection{
		net:         net,
		transport:   transport,
		isHTTP:      factory.decodeHTTP && (tcp.SrcPort == 80 || tcp.DstPort == 80),
		isPOP3:      factory.decodePOP3 && (tcp.SrcPort == 110 || tcp.DstPort == 110),
		reversed:    tcp.SrcPort == 80,
		tcpstate:    reassembly.NewTCPSimpleFSM(fsmOptions),
		ident:       filepath.Clean(fmt.Sprintf("%s-%s", net, transport)),
		optchecker:  reassembly.NewTCPOptionCheck(),
		firstPacket: ac.GetCaptureInfo().Timestamp,
	}

	if stream.isHTTP {
		stream.client = &httpReader{
			bytes:    make(chan []byte),
			ident:    filepath.Clean(fmt.Sprintf("%s-%s", net, transport)),
			hexdump:  c.HexDump,
			parent:   stream,
			isClient: true,
		}
		stream.server = &httpReader{
			bytes:   make(chan []byte),
			ident:   filepath.Clean(fmt.Sprintf("%s-%s", net.Reverse(), transport.Reverse())),
			hexdump: c.HexDump,
			parent:  stream,
		}

		// kickoff decoders for client and server
		factory.wg.Add(2)
		go stream.client.Run(&factory.wg)
		go stream.server.Run(&factory.wg)
	}

	if stream.isPOP3 {
		stream.client = &pop3Reader{
			bytes:    make(chan []byte),
			ident:    filepath.Clean(fmt.Sprintf("%s-%s", net, transport)),
			hexdump:  c.HexDump,
			parent:   stream,
			isClient: true,
		}
		stream.server = &pop3Reader{
			bytes:   make(chan []byte),
			ident:   filepath.Clean(fmt.Sprintf("%s-%s", net.Reverse(), transport.Reverse())),
			hexdump: c.HexDump,
			parent:  stream,
		}

		// kickoff decoders for client and server
		factory.wg.Add(2)
		go stream.client.Run(&factory.wg)
		go stream.server.Run(&factory.wg)
	}

	// TODO: capture unknown protocol stream and write to disk

	return stream
}

func (factory *tcpConnectionFactory) WaitGoRoutines() {
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
		reassemblyStats.rejectFsm++
		if !t.fsmerr {
			t.fsmerr = true
			reassemblyStats.rejectConnFsm++
		}
		if !c.IgnoreFSMerr {
			return false
		}
	}
	// Options
	err := t.optchecker.Accept(tcp, ci, dir, nextSeq, start)
	if err != nil {
		logReassemblyError("OptionChecker", "%s: Packet rejected by OptionChecker: %s\n", t.ident, err)
		reassemblyStats.rejectOpt++
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
		reassemblyStats.rejectOpt++
	}
	return accept
}

func (t *tcpConnection) ReassembledSG(sg reassembly.ScatterGather, ac reassembly.AssemblerContext) {

	dir, start, end, skip := sg.Info()
	length, saved := sg.Lengths()

	// update stats
	sgStats := sg.Stats()
	if skip > 0 {
		reassemblyStats.missedBytes += skip
	}

	reassemblyStats.sz += length - saved
	reassemblyStats.pkt += sgStats.Packets
	if sgStats.Chunks > 1 {
		reassemblyStats.reassembled++
	}
	reassemblyStats.outOfOrderPackets += sgStats.QueuedPackets
	reassemblyStats.outOfOrderBytes += sgStats.QueuedBytes
	if length > reassemblyStats.biggestChunkBytes {
		reassemblyStats.biggestChunkBytes = length
	}
	if sgStats.Packets > reassemblyStats.biggestChunkPackets {
		reassemblyStats.biggestChunkPackets = sgStats.Packets
	}
	if sgStats.OverlapBytes != 0 && sgStats.OverlapPackets == 0 {
		fmt.Printf("bytes:%d, pkts:%d\n", sgStats.OverlapBytes, sgStats.OverlapPackets)
		panic("Invalid overlap")
	}
	reassemblyStats.overlapBytes += sgStats.OverlapBytes
	reassemblyStats.overlapPackets += sgStats.OverlapPackets

	var ident string
	if dir == reassembly.TCPDirClientToServer {
		ident = fmt.Sprintf("%v %v(%s): ", t.net, t.transport, dir)
	} else {
		ident = fmt.Sprintf("%v %v(%s): ", t.net.Reverse(), t.transport.Reverse(), dir)
	}

	logReassemblyDebug("%s: SG reassembled packet with %d bytes (start:%v,end:%v,skip:%d,saved:%d,nb:%d,%d,overlap:%d,%d)\n", ident, length, start, end, skip, saved, sgStats.Packets, sgStats.Chunks, sgStats.OverlapBytes, sgStats.OverlapPackets)
	if skip == -1 && c.AllowMissingInit {
		// this is allowed
	} else if skip != 0 {
		// Missing bytes in stream: do not even try to parse it
		return
	}

	// TODO add types and call handler to allow decoding several app layer protocols
	data := sg.Fetch(length)
	if t.isHTTP {
		if length > 0 {
			if c.HexDump {
				logReassemblyDebug("Feeding http with:\n%s", hex.Dump(data))
			}
			if dir == reassembly.TCPDirClientToServer && !t.reversed {
				t.client.BytesChan() <- data
			} else {
				t.server.BytesChan() <- data
			}
		}
	} else if t.isPOP3 {
		if length > 0 {
			if c.HexDump {
				logReassemblyDebug("Feeding POP3 with:\n%s", hex.Dump(data))
			}
			if dir == reassembly.TCPDirClientToServer && !t.reversed {
				t.client.BytesChan() <- data
			} else {
				t.server.BytesChan() <- data
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

	tcp := packet.Layer(layers.LayerTypeTCP)
	if tcp != nil {
		tcp := tcp.(*layers.TCP)
		if c.Checksum {
			err := tcp.SetNetworkLayerForChecksum(packet.NetworkLayer())
			if err != nil {
				log.Fatalf("Failed to set network layer for checksum: %s\n", err)
			}
		}
		reassemblyStats.totalsz += len(tcp.Payload)

		assembler.AssembleWithContext(packet.NetworkLayer().NetworkFlow(), tcp, &Context{
			CaptureInfo: packet.Metadata().CaptureInfo,
		})
	}

	// flush connections in interval
	if count%c.FlushEvery == 0 {
		ref := packet.Metadata().CaptureInfo.Timestamp
		// flushed, closed :=
		//fmt.Println("FlushWithOptions")
		assembler.FlushWithOptions(reassembly.FlushOptions{T: ref.Add(-c.ClosePendingTimeOut), TC: ref.Add(-c.CloseInactiveTimeOut)})
		//fmt.Println("FlushWithOptions done")

		// TODO: log into file when debugging is enabled
		// fmt.Printf("Forced flush: %d flushed, %d closed (%s)\n", flushed, closed, ref, ref.Add(-timeout))
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
		fmt.Println("HTTP AssembleWithContext timeout", packet.NetworkLayer().NetworkFlow(), packet.TransportLayer().TransportFlow())
		fmt.Println(assembler.Dump())
	}
}

func CleanupReassembly(wait bool) {

	if c.Debug {
		reassemblyLog.Println("StreamPool:")
		reassemblyLog.Println(StreamPool.DumpString())
	}

	// wait for stream reassembly to finish
	if c.WaitForConnections || wait {
		if !Quiet {
			fmt.Println("\nwaiting for last streams to finish processing or time-out, timeout:", c.ClosePendingTimeOut)
			fmt.Println("hit ctrl-C to force quit")
		}
		streamFactory.WaitGoRoutines()
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
		reassemblyLog.Printf("HTTPEncoder: Processed %v packets (%v bytes) in %v (errors: %v, type:%v)\n", count, dataBytes, time.Since(start), numErrors, len(errorsMap))
		errorsMapMutex.Unlock()

		// print configuration
		// print configuration as table
		tui.Table(reassemblyLogFileHandle, []string{"Reassembly Setting", "Value"}, [][]string{
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

		fmt.Println() // add a newline
		printProgress(1, 1)
		fmt.Println("")

		rows := [][]string{}
		if !c.NoDefrag {
			rows = append(rows, []string{"IPdefrag", strconv.Itoa(reassemblyStats.ipdefrag)})
		}
		rows = append(rows, []string{"missed bytes", strconv.Itoa(reassemblyStats.missedBytes)})
		rows = append(rows, []string{"total packets", strconv.Itoa(reassemblyStats.pkt)})
		rows = append(rows, []string{"rejected FSM", strconv.Itoa(reassemblyStats.rejectFsm)})
		rows = append(rows, []string{"rejected Options", strconv.Itoa(reassemblyStats.rejectOpt)})
		rows = append(rows, []string{"reassembled bytes", strconv.Itoa(reassemblyStats.sz)})
		rows = append(rows, []string{"total TCP bytes", strconv.Itoa(reassemblyStats.totalsz)})
		rows = append(rows, []string{"conn rejected FSM", strconv.Itoa(reassemblyStats.rejectConnFsm)})
		rows = append(rows, []string{"reassembled chunks", strconv.Itoa(reassemblyStats.reassembled)})
		rows = append(rows, []string{"out-of-order packets", strconv.Itoa(reassemblyStats.outOfOrderPackets)})
		rows = append(rows, []string{"out-of-order bytes", strconv.Itoa(reassemblyStats.outOfOrderBytes)})
		rows = append(rows, []string{"biggest-chunk packets", strconv.Itoa(reassemblyStats.biggestChunkPackets)})
		rows = append(rows, []string{"biggest-chunk bytes", strconv.Itoa(reassemblyStats.biggestChunkBytes)})
		rows = append(rows, []string{"overlap packets", strconv.Itoa(reassemblyStats.overlapPackets)})
		rows = append(rows, []string{"overlap bytes", strconv.Itoa(reassemblyStats.overlapBytes)})

		tui.Table(reassemblyLogFileHandle, []string{"TCP Stat", "Value"}, rows)

		if numErrors != 0 {
			rows = [][]string{}
			for e := range errorsMap {
				rows = append(rows, []string{e, strconv.FormatUint(uint64(errorsMap[e]), 10)})
			}
			tui.Table(reassemblyLogFileHandle, []string{"Error Subject", "Count"}, rows)
		}

		reassemblyLog.Println("\nencountered", numErrors, "errors during processing.", "HTTP requests", requests, " responses", responses)
	}
}
