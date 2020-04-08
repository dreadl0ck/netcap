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
	"github.com/namsral/flag"
	"fmt"
	"github.com/dreadl0ck/gopacket/ip4defrag"
	"log"
	"net/http"
	"path/filepath"
	"sync"
	"time"

	"github.com/dreadl0ck/netcap/types"

	"github.com/dreadl0ck/gopacket"
	"github.com/dreadl0ck/gopacket/layers"
	"github.com/dreadl0ck/gopacket/reassembly"
)

// flags
var (
	flushevery       = flag.Int("flushevery", 100, "flush assembler every N packets")
	//flagCloseTimeOut = flag.Int("tcp-close-timeout", 60, "close tcp streams if older than X seconds (set to 0 to keep long lived streams alive)")
	//flagTimeOut      = flag.Int("tcp-timeout", 60, "close streams waiting for packets older than X seconds")

	nodefrag         = flag.Bool("nodefrag", false, "if true, do not do IPv4 defrag")
	checksum         = flag.Bool("checksum", false, "check TCP checksum")
	nooptcheck       = flag.Bool("nooptcheck", false, "do not check TCP options (useful to ignore MSS on captures with TSO)")
	ignorefsmerr     = flag.Bool("ignorefsmerr", false, "ignore TCP FSM errors")
	allowmissinginit = flag.Bool("allowmissinginit", false, "support streams without SYN/SYN+ACK/ACK sequence")

	debug   = flag.Bool("debug", false, "display debug information")
	hexdump = flag.Bool("hexdump-http", false, "dump HTTP request/response as hex")

	writeincomplete = flag.Bool("writeincomplete", false, "write incomplete response")
	memprofile      = flag.String("memprofile", "", "write memory profile")

	numErrors   uint
	requests    = 0
	responses   = 0
	mu          sync.Mutex

	closeTimeout time.Duration = time.Hour * 24 // time.Duration(*flagCloseTimeOut) // Closing inactive
	timeout      time.Duration = time.Second * 30 // * time.Duration(*flagTimeOut)      // Pending bytes

	defragger     = ip4defrag.NewIPv4Defragmenter()
	streamFactory = &tcpStreamFactory{}
	StreamPool    = reassembly.NewStreamPool(streamFactory)

	count     = 0
	dataBytes = int64(0)
	start     = time.Now()

	errorsMap      = make(map[string]uint)
	errorsMapMutex sync.Mutex

	FileStorage string
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

type tcpStreamFactory struct {
	wg     sync.WaitGroup
	decodeHTTP bool
	decodePOP3 bool
}

var fsmOptions = reassembly.TCPSimpleFSMOptions{
	SupportMissingEstablishment: *allowmissinginit,
}

func (factory *tcpStreamFactory) New(net, transport gopacket.Flow, tcp *layers.TCP, ac reassembly.AssemblerContext) reassembly.Stream {

	logDebug("* NEW: %s %s\n", net, transport)

	stream := &tcpStream{
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
			hexdump:  *hexdump,
			parent:   stream,
			isClient: true,
		}
		stream.server = &httpReader{
			bytes:   make(chan []byte),
			ident:   filepath.Clean(fmt.Sprintf("%s-%s", net.Reverse(), transport.Reverse())),
			hexdump: *hexdump,
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
			hexdump:  *hexdump,
			parent:   stream,
			isClient: true,
		}
		stream.server = &pop3Reader{
			bytes:   make(chan []byte),
			ident:   filepath.Clean(fmt.Sprintf("%s-%s", net.Reverse(), transport.Reverse())),
			hexdump: *hexdump,
			parent:  stream,
		}

		// kickoff decoders for client and server
		factory.wg.Add(2)
		go stream.client.Run(&factory.wg)
		go stream.server.Run(&factory.wg)
	}

	return stream
}

func (factory *tcpStreamFactory) WaitGoRoutines() {
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
 * TCP stream
 */

/* It's a connection (bidirectional) */
type tcpStream struct {
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

	requests  []*http.Request
	responses []*http.Response

	pop3Requests  []*types.POP3Request
	pop3Responses []*types.POP3Response

	// if set, indicates that either client or server http reader was closed already
	last bool

	sync.Mutex
}

func (t *tcpStream) Accept(tcp *layers.TCP, ci gopacket.CaptureInfo, dir reassembly.TCPFlowDirection, nextSeq reassembly.Sequence, start *bool, ac reassembly.AssemblerContext) bool {
	// FSM
	if !t.tcpstate.CheckState(tcp, dir) {
		logError("FSM", "%s: Packet rejected by FSM (state:%s)\n", t.ident, t.tcpstate.String())
		reassemblyStats.rejectFsm++
		if !t.fsmerr {
			t.fsmerr = true
			reassemblyStats.rejectConnFsm++
		}
		if !*ignorefsmerr {
			return false
		}
	}
	// Options
	err := t.optchecker.Accept(tcp, ci, dir, nextSeq, start)
	if err != nil {
		logError("OptionChecker", "%s: Packet rejected by OptionChecker: %s\n", t.ident, err)
		reassemblyStats.rejectOpt++
		if !*nooptcheck {
			return false
		}
	}
	// Checksum
	accept := true
	if *checksum {
		c, err := tcp.ComputeChecksum()
		if err != nil {
			logError("ChecksumCompute", "%s: Got error computing checksum: %s\n", t.ident, err)
			accept = false
		} else if c != 0x0 {
			logError("Checksum", "%s: Invalid checksum: 0x%x\n", t.ident, c)
			accept = false
		}
	}
	if !accept {
		reassemblyStats.rejectOpt++
	}
	return accept
}

func (t *tcpStream) ReassembledSG(sg reassembly.ScatterGather, ac reassembly.AssemblerContext) {

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

	logDebug("%s: SG reassembled packet with %d bytes (start:%v,end:%v,skip:%d,saved:%d,nb:%d,%d,overlap:%d,%d)\n", ident, length, start, end, skip, saved, sgStats.Packets, sgStats.Chunks, sgStats.OverlapBytes, sgStats.OverlapPackets)
	if skip == -1 && *allowmissinginit {
		// this is allowed
	} else if skip != 0 {
		// Missing bytes in stream: do not even try to parse it
		return
	}

	// TODO add types and call handler to allow decoding several app layer protocols
	data := sg.Fetch(length)
	if t.isHTTP {
		if length > 0 {
			if *hexdump {
				logDebug("Feeding http with:\n%s", hex.Dump(data))
			}
			if dir == reassembly.TCPDirClientToServer && !t.reversed {
				t.client.BytesChan() <- data
			} else {
				t.server.BytesChan() <- data
			}
		}
	} else if t.isPOP3 {
		if length > 0 {
			//fmt.Printf("Feeding POP3 with:\n%s", hex.Dump(data))
			if dir == reassembly.TCPDirClientToServer && !t.reversed {
				t.client.BytesChan() <- data
			} else {
				t.server.BytesChan() <- data
			}
		}
	}
}

func (t *tcpStream) ReassemblyComplete(ac reassembly.AssemblerContext) bool {
	logDebug("%s: Connection closed\n", t.ident)
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
	if !*nodefrag {
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
			logDebug("Fragment...\n")
			return
		}
		if newip4.Length != l {
			reassemblyStats.ipdefrag++
			logDebug("Decoding re-assembled packet: %s\n", newip4.NextLayerType())
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
		if *checksum {
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
	if count%*flushevery == 0 {
		ref := packet.Metadata().CaptureInfo.Timestamp
		// flushed, closed :=
		//fmt.Println("FlushWithOptions")
		assembler.FlushWithOptions(reassembly.FlushOptions{T: ref.Add(-timeout), TC: ref.Add(-closeTimeout)})
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