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
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/dreadl0ck/gopacket"
	"github.com/dreadl0ck/gopacket/layers"
	"github.com/dreadl0ck/gopacket/reassembly"
)

// flags
var (
	flushevery       = flag.Int("flushevery", 100000, "flush assembler every N packets")
	nodefrag         = flag.Bool("nodefrag", false, "if true, do not do IPv4 defrag")
	checksum         = flag.Bool("checksum", false, "check TCP checksum")
	nooptcheck       = flag.Bool("nooptcheck", false, "do not check TCP options (useful to ignore MSS on captures with TSO)")
	ignorefsmerr     = flag.Bool("ignorefsmerr", false, "ignore TCP FSM errors")
	allowmissinginit = flag.Bool("allowmissinginit", false, "support streams without SYN/SYN+ACK/ACK sequence")
	verbose          = flag.Bool("verbose", false, "be verbose")
	debug            = flag.Bool("debug", false, "display debug information")
	quiet            = flag.Bool("quiet", true, "be quiet regarding errors")
	nohttp           = flag.Bool("nohttp", false, "disable HTTP parsing")
	fileStorage      = flag.String("fileStorage", "", "path to create file for HTTP 200 OK responses")
	writeincomplete  = flag.Bool("writeincomplete", false, "write incomplete response")
	hexdump          = flag.Bool("dump", false, "dump HTTP request/response as hex")
	memprofile       = flag.String("memprofile", "", "write memory profile")

	flagCloseTimeOut = flag.Int("tcp-close-timeout", 0, "close tcp streams if older than X seconds (set to 0 to keep long lived streams alive)")
	flagTimeOut      = flag.Int("tcp-timeout", 600, "close streams waiting for packets older than X seconds")

	outputLevel int
	numErrors   uint
	requests    = 0
	responses   = 0
	mu          sync.Mutex

	closeTimeout time.Duration = time.Second * time.Duration(*flagCloseTimeOut) // Closing inactive
	timeout      time.Duration = time.Second * time.Duration(*flagTimeOut)      // Pending bytes
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
 * The TCP factory: returns a new Stream
 */

type tcpStreamFactory struct {
	wg     sync.WaitGroup
	doHTTP bool
}

func (factory *tcpStreamFactory) New(net, transport gopacket.Flow, tcp *layers.TCP, ac reassembly.AssemblerContext) reassembly.Stream {

	logDebug("* NEW: %s %s\n", net, transport)
	fsmOptions := reassembly.TCPSimpleFSMOptions{
		SupportMissingEstablishment: *allowmissinginit,
	}

	stream := &tcpStream{
		net:         net,
		transport:   transport,
		isDNS:       tcp.SrcPort == 53 || tcp.DstPort == 53,
		isHTTP:      (tcp.SrcPort == 80 || tcp.DstPort == 80) && factory.doHTTP,
		reversed:    tcp.SrcPort == 80,
		tcpstate:    reassembly.NewTCPSimpleFSM(fsmOptions),
		ident:       fmt.Sprintf("%s:%s", net, transport),
		optchecker:  reassembly.NewTCPOptionCheck(),
		firstPacket: ac.GetCaptureInfo().Timestamp,
	}

	if stream.isHTTP {
		stream.client = httpReader{
			bytes:    make(chan []byte),
			ident:    fmt.Sprintf("%s %s", net, transport),
			hexdump:  *hexdump,
			parent:   stream,
			isClient: true,
		}
		stream.server = httpReader{
			bytes:   make(chan []byte),
			ident:   fmt.Sprintf("%s %s", net.Reverse(), transport.Reverse()),
			hexdump: *hexdump,
			parent:  stream,
		}

		// kickoff http decoders for client and server
		factory.wg.Add(2)
		go stream.client.run(&factory.wg)
		go stream.server.run(&factory.wg)
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
	isDNS    bool
	isHTTP   bool
	reversed bool
	ident    string

	client httpReader
	server httpReader

	firstPacket time.Time

	requests  []*http.Request
	responses []*http.Response

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
	if t.isDNS {
		var (
			dns     = &layers.DNS{}
			decoded []gopacket.LayerType
		)
		if len(data) < 2 {
			if len(data) > 0 {
				sg.KeepFrom(0)
			}
			return
		}

		var (
			dnsSize = binary.BigEndian.Uint16(data[:2])
			missing = int(dnsSize) - len(data[2:])
		)

		logDebug("dnsSize: %d, missing: %d\n", dnsSize, missing)

		if missing > 0 {
			logInfo("Missing some bytes: %d\n", missing)
			sg.KeepFrom(0)
			return
		}

		var (
			p   = gopacket.NewDecodingLayerParser(layers.LayerTypeDNS, dns)
			err = p.DecodeLayers(data[2:], &decoded)
		)
		if err != nil {
			logError("DNS-parser", "Failed to decode DNS: %v\n", err)
		} else {
			logDebug("DNS: %s\n", gopacket.LayerDump(dns))
		}
		if len(data) > 2+int(dnsSize) {
			sg.KeepFrom(2 + int(dnsSize))
		}
	} else if t.isHTTP {
		if length > 0 {
			if *hexdump {
				logDebug("Feeding http with:\n%s", hex.Dump(data))
			}
			if dir == reassembly.TCPDirClientToServer && !t.reversed {
				t.client.bytes <- data
			} else {
				t.server.bytes <- data
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
			close(t.client.bytes)
		}()
		func() {
			defer recovery()
			close(t.server.bytes)
		}()
	}
	// do not remove the connection to allow last ACK
	return false
}
