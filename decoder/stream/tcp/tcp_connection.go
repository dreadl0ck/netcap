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
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"reflect"
	"runtime/pprof"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/dreadl0ck/gopacket"
	"github.com/dreadl0ck/gopacket/layers"
	"github.com/evilsocket/islazy/tui"
	"go.uber.org/zap"

	decoderconfig "github.com/dreadl0ck/netcap/decoder/config"
	"github.com/dreadl0ck/netcap/decoder/core"
	"github.com/dreadl0ck/netcap/decoder/stream"
	"github.com/dreadl0ck/netcap/decoder/stream/udp"
	streamutils "github.com/dreadl0ck/netcap/decoder/stream/utils"
	"github.com/dreadl0ck/netcap/defaults"
	"github.com/dreadl0ck/netcap/dpi"
	"github.com/dreadl0ck/netcap/reassembly"
	"github.com/dreadl0ck/netcap/utils"
)

var (
	start                   = time.Now()
	errorsMap               = make(map[string]uint)
	errorsMapMutex          sync.Mutex
	reassemblyLogFileHandle *os.File
)

// NumSavedTCPConns returns the number of saved TCP connections.
func NumSavedTCPConns() int64 {
	streamutils.Stats.Lock()
	defer streamutils.Stats.Unlock()

	return streamutils.Stats.SavedTCPConnections
}

/*
 * TCP Connection
 */

// internal structure that describes a bi-directional TCP connection
// It implements the reassembly.Stream interface to handle the incoming data
// and manage the stream lifecycle
// this structure has an optimized field order to avoid excessive padding.
type tcpConnection struct {
	sync.Mutex
	net, transport gopacket.Flow

	optchecker reassembly.TCPOptionCheck

	merged      core.DataFragments
	firstPacket time.Time

	client streamReader
	server streamReader

	ident    string
	decoder  core.StreamDecoderInterface
	tcpstate *reassembly.TCPSimpleFSM

	wasMerged bool
	fsmerr    bool
}

// Accept decides whether the TCP packet should be accepted
// start could be modified to force a start even if no SYN have been seen.
func (t *tcpConnection) Accept(tcp *layers.TCP, dir reassembly.TCPFlowDirection, nextSeq reassembly.Sequence) bool {
	// Finite State Machine
	if !t.tcpstate.CheckState(tcp, dir) {

		reassemblyLog.Debug("packet rejected by FSM", zap.String("ident", t.ident), zap.String("state", t.tcpstate.String()))

		streamutils.Stats.Lock()
		streamutils.Stats.RejectFsm++

		if !t.fsmerr {
			t.fsmerr = true
			streamutils.Stats.RejectConnFsm++
		}
		streamutils.Stats.Unlock()

		if !decoderconfig.Instance.IgnoreFSMerr {
			return false
		}
	}

	// TCP Options
	err := t.optchecker.Accept(tcp, dir, nextSeq)
	if err != nil {
		reassemblyLog.Debug("packet rejected by OptionChecker", zap.String("ident", t.ident), zap.Error(err))
		streamutils.Stats.Lock()
		streamutils.Stats.RejectOpt++
		streamutils.Stats.Unlock()

		if !decoderconfig.Instance.NoOptCheck {
			return false
		}
	}

	// TCP Checksum
	accept := true

	if decoderconfig.Instance.Checksum {
		chk, errChk := tcp.ComputeChecksum()
		if errChk != nil {
			reassemblyLog.Debug("error computing checksum", zap.String("ident", t.ident), zap.Error(errChk))

			accept = false
		} else if chk != 0x0 {
			reassemblyLog.Debug("invalid checksum", zap.String("checksum", fmt.Sprintf("0x%x", chk)), zap.String("ident", t.ident))

			accept = false
		}
	}

	// stats
	if !accept {
		streamutils.Stats.Lock()
		streamutils.Stats.RejectOpt++
		streamutils.Stats.Unlock()
	}

	return accept
}

func (t *tcpConnection) updateStats(sg reassembly.ScatterGather, skip int, length int, saved int, start bool, end bool, dir reassembly.TCPFlowDirection) {
	sgStats := sg.Stats()

	streamutils.Stats.Lock()
	if skip > 0 {
		streamutils.Stats.MissedBytes += int64(skip)
	}

	streamutils.Stats.Sz += int64(length - saved)
	streamutils.Stats.Pkt += int64(sgStats.Packets)
	if sgStats.Chunks > 1 {
		streamutils.Stats.Reassembled++
	}
	streamutils.Stats.OutOfOrderPackets += int64(sgStats.QueuedPackets)
	streamutils.Stats.OutOfOrderBytes += int64(sgStats.QueuedBytes)

	if int64(length) > streamutils.Stats.BiggestChunkBytes {
		streamutils.Stats.BiggestChunkBytes = int64(length)
	}

	if int64(sgStats.Packets) > streamutils.Stats.BiggestChunkPackets {
		streamutils.Stats.BiggestChunkPackets = int64(sgStats.Packets)
	}

	if sgStats.OverlapBytes != 0 && sgStats.OverlapPackets == 0 {
		reassemblyLog.Warn("reassembledSG: invalid overlap",
			zap.Int("bytes", sgStats.OverlapBytes),
			zap.Int("packets", sgStats.OverlapPackets),
		)
	}

	streamutils.Stats.OverlapBytes += int64(sgStats.OverlapBytes)
	streamutils.Stats.OverlapPackets += int64(sgStats.OverlapPackets)
	streamutils.Stats.Unlock()

	var ident string
	if dir == reassembly.TCPDirClientToServer {
		ident = fmt.Sprintf("%v %v(%s): ", t.net, t.transport, dir)
	} else {
		ident = fmt.Sprintf("%v %v(%s): ", t.net.Reverse(), t.transport.Reverse(), dir)
	}

	reassemblyLog.Debug("SG reassembled packet",
		zap.String("ident", ident),
		zap.Int("length", length),
		zap.Bool("start", start),
		zap.Bool("end", end),
		zap.Int("skip", skip),
		zap.Int("saved", saved),
		zap.Int("packets", sgStats.Packets),
		zap.Int("chunks", sgStats.Chunks),
		zap.Int("overlapBytes", sgStats.OverlapBytes),
		zap.Int("overlapPackets", sgStats.OverlapPackets),
	)
}

func (t *tcpConnection) feedData(dir reassembly.TCPFlowDirection, data []byte, ac reassembly.AssemblerContext) {
	// fmt.Println(t.ident, "feedData", ansi.White, dir, ansi.Cyan, len(data), ansi.Yellow, ac.GetCaptureInfo().Timestamp.Format("2006-02-01 15:04:05.000000"), ansi.Reset)
	// fmt.Println(hex.Dump(data))

	// Copy the data before passing it to the handler
	// Because the passed in buffer can be reused as soon as the ReassembledSG function returned
	dataCpy := make([]byte, len(data))
	l := copy(dataCpy, data)

	if l != len(data) {
		log.Fatal("l != len(data): ", l, " != ", len(data), " ident:", t.ident)
	}

	ti := time.Now()

	// pass data either to client or server
	if dir == reassembly.TCPDirClientToServer {
		t.client.DataChan() <- &core.StreamData{
			RawData:          dataCpy,
			AssemblerContext: ac,
			Dir:              dir,
		}
	} else {
		t.server.DataChan() <- &core.StreamData{
			RawData:          dataCpy,
			AssemblerContext: ac,
			Dir:              dir,
		}
	}

	tcpStreamFeedDataTime.WithLabelValues(dir.String()).Set(float64(time.Since(ti).Nanoseconds()))
}

// ReassembledSG is called zero or more times and delivers the data for a stream
// The ScatterGather buffer is reused after each Reassembled call
// so it's important to copy anything you need out of it (or use KeepFrom()).
func (t *tcpConnection) ReassembledSG(sg reassembly.ScatterGather, ac reassembly.AssemblerContext) {
	length, saved := sg.Lengths()
	dir, startTime, end, skip := sg.Info()

	// update stats
	t.updateStats(sg, skip, length, saved, startTime, end, dir)

	if skip == -1 && decoderconfig.Instance.AllowMissingInit {
		// this is allowed
	} else if skip != 0 {
		// Missing bytes in stream: do not even try to parse it
		return
	}

	data := sg.Fetch(length)

	// fmt.Println("got raw data:", len(data), ac.GetCaptureInfo().Timestamp, "\n", hex.Dump(data))

	if length > 0 {
		if decoderconfig.Instance.HexDump {
			reassemblyLog.Debug("feeding stream reader",
				zap.String("data", hex.Dump(data)),
			)
		}

		t.feedData(dir, data, ac)
	}
}

func (t *tcpConnection) reorder(ac reassembly.AssemblerContext, firstFlow gopacket.Flow) {
	// fmt.Println(t.ident, "t.firstPacket:", t.firstPacket, "ac.Timestamp", ac.GetCaptureInfo().Timestamp, "firstFlow", firstFlow)
	// fmt.Println(t.ident, !t.firstPacket.Equal(ac.GetCaptureInfo().Timestamp), "&&", t.firstPacket.After(ac.GetCaptureInfo().Timestamp))

	// is this packet older than the oldest packet we saw for this connection?
	// if yes, if check the direction of the client is correct
	if !t.firstPacket.Equal(ac.GetCaptureInfo().Timestamp) && t.firstPacket.After(ac.GetCaptureInfo().Timestamp) { // update first packet timestamp on connection
		t.Lock()
		t.firstPacket = ac.GetCaptureInfo().Timestamp
		t.Unlock()

		if t.client != nil && t.server != nil {
			// check if firstFlow is identical or needs to be flipped
			if !(t.client.Network() == firstFlow) { // flip
				t.client.SetClient(false)
				t.server.SetClient(true)

				t.Lock()
				t.ident = utils.ReverseFlowIdent(t.ident)
				// fmt.Println("flip! new", ansi.Red+t.ident+ansi.Reset, t.firstPacket)

				t.client, t.server = t.server, t.client
				t.transport, t.net = t.transport.Reverse(), t.net.Reverse()

				// fix directions for all data fragments
				for _, d := range t.client.DataSlice() {
					d.SetDirection(reassembly.TCPDirClientToServer)
				}

				for _, d := range t.server.DataSlice() {
					d.SetDirection(reassembly.TCPDirServerToClient)
				}
				t.Unlock()
			}
		}
	}
}

// ReassemblyComplete is called when assembly decides there is
// no more data for this stream, either because a FIN or RST packet
// was seen, or because the stream has timed out without any new
// packet data (due to a call to FlushCloseOlderThan).
// It should return true if the connection should be removed from the pool
// It can return false if it want to see subsequent packets with Accept(), e.g. to
// see FIN-ACK, for deeper state-machine analysis.
func (t *tcpConnection) ReassemblyComplete(ac reassembly.AssemblerContext, firstFlow gopacket.Flow, reason string) bool {
	// reorder the stream fragments
	t.reorder(ac, firstFlow)

	reassemblyLog.Debug("ReassemblyComplete",
		zap.String("ident", t.ident),
		zap.String("reason", reason),
		zap.Bool("clientIsNil", t.client == nil),
		zap.Bool("clientSaved:", t.client.Saved()),
		zap.Bool("serverIsNil", t.server == nil),
		zap.Bool("serverSaved:", t.server.Saved()),
	)

	ti := time.Now()

	// save data for the current stream
	if t.server != nil && !t.client.Saved() {
		t.client.MarkSaved()

		t.sortAndMergeFragments()

		// save the full conversation to disk if enabled
		err := streamutils.SaveConversation("TCP", t.merged, t.client.Ident(), t.client.FirstPacket(), t.client.Transport())
		if err != nil {
			reassemblyLog.Error("failed to save stream", zap.Error(err), zap.String("ident", t.client.Ident()))
		}
		tcpStreamProcessingTime.WithLabelValues(reassembly.TCPDirClientToServer.String()).Set(float64(time.Since(ti).Nanoseconds()))

		// decode the actual conversation.
		// this needs to be invoked only once, and since ReassemblyComplete is invoked for each side of the connection
		// decode should be called either when processing the client or the server stream
		t.decode()
	}

	if t.server != nil && !t.server.Saved() {
		t.server.MarkSaved()

		t.sortAndMergeFragments()

		// server
		saveTCPServiceBanner(t.server)
		tcpStreamProcessingTime.WithLabelValues(reassembly.TCPDirServerToClient.String()).Set(float64(time.Since(ti).Nanoseconds()))
	}

	reassemblyLog.Debug("stream closed",
		zap.String("ident", t.ident),
	)

	// optionally, do not remove the connection to allow last ACK
	return decoderconfig.Instance.RemoveClosedStreams
}

func (t *tcpConnection) decode() {

	t.Lock()
	defer t.Unlock()

	// choose the decoder to run against the data stream
	var (
		cr, sr = t.client.DataSlice().First(), t.server.DataSlice().First()
		found  bool
	)

	conv := &core.ConversationInfo{
		Data:              t.merged,
		Ident:             t.ident,
		FirstClientPacket: t.client.FirstPacket(),
		FirstServerPacket: t.server.FirstPacket(),
		ClientIP:          t.client.Network().Src().String(),
		ServerIP:          t.client.Network().Dst().String(),
		ClientPort:        utils.DecodePort(t.client.Transport().Src().Raw()),
		ServerPort:        utils.DecodePort(t.client.Transport().Dst().Raw()),
	}

	// make a good first guess based on the destination port of the connection
	if sd, exists := stream.DefaultStreamDecoders[utils.DecodePort(t.server.Transport().Dst().Raw())]; exists {
		if sd.Transport() == core.TCP || sd.Transport() == core.All {
			if sd.GetReaderFactory() != nil && sd.CanDecodeStream(cr, sr) {
				t.decoder = sd.GetReaderFactory().New(conv)
				found = true
			}
		}
	}

	// if no stream decoder for the port was found, or the stream decoder did not match
	// try all available decoders and use the first one that matches
	if !found {
		for _, sd := range stream.DefaultStreamDecoders {
			if sd.Transport() == core.TCP || sd.Transport() == core.All {
				if sd.GetReaderFactory() != nil && sd.CanDecodeStream(cr, sr) {
					t.decoder = sd.GetReaderFactory().New(conv)
					break
				}
			}
		}
	}

	// call the decoder if one was found
	if t.decoder != nil {
		ti := time.Now()

		// call the associated decoder
		t.decoder.Decode()

		tcpStreamDecodeTime.WithLabelValues(reflect.TypeOf(t.decoder).String()).Set(float64(time.Since(ti).Nanoseconds()))
	}
}

var aMu sync.Mutex

// ReassemblePacket takes care of submitting a TCP / UDP packet to the reassembly.
func ReassemblePacket(packet gopacket.Packet, assembler *reassembly.Assembler) {

	// TODO: make transport layer reassembler configurable
	// prevent passing any non TCP packets in here
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {

		// handle UDP stream reconstruction
		udpLayer := packet.Layer(layers.LayerTypeUDP)
		if udpLayer != nil {
			udp.Streams.HandleUDP(packet, udpLayer)
		}

		return
	}

	// lock to sync with read on destroy
	streamutils.Stats.Lock()
	streamutils.Stats.Count++
	streamutils.Stats.DataBytes += int64(len(packet.Data()))
	streamutils.Stats.Unlock()

	// defrag the IPv4 packet if desired
	ip4Layer := packet.Layer(layers.LayerTypeIPv4)
	if ip4Layer != nil && decoderconfig.Instance.DefragIPv4 {

		var (
			ip4         = ip4Layer.(*layers.IPv4)
			l           = ip4.Length
			newip4, err = StreamFactory.defragger.DefragIPv4(ip4)
		)

		if err != nil {
			log.Fatalln("error while de-fragmenting", err)
		} else if newip4 == nil {
			reassemblyLog.Debug("fragment received...")

			return
		}

		if newip4.Length != l {
			streamutils.Stats.IPdefrag++

			reassemblyLog.Debug("decoding re-assembled packet", zap.String("layer", newip4.NextLayerType().String()))

			pb, ok := packet.(gopacket.PacketBuilder)
			if !ok {
				panic("Not a PacketBuilder")
			}

			nextDecoder := newip4.NextLayerType()
			if err = nextDecoder.Decode(newip4.Payload, pb); err != nil {
				fmt.Println("failed to decode ipv4:", err)
			}
		}
	}

	tcp := tcpLayer.(*layers.TCP)

	if decoderconfig.Instance.Checksum {
		err := tcp.SetNetworkLayerForChecksum(packet.NetworkLayer())
		if err != nil {
			log.Fatalf("Failed to set network layer for checksum: %s\n", err)
		}
	}

	streamutils.Stats.Lock()
	streamutils.Stats.Totalsz += int64(len(tcp.Payload))
	streamutils.Stats.Unlock()

	// for debugging:
	// assembleWithContextTimeout(packet, assembler, tcp)
	aMu.Lock()
	assembler.AssembleWithContext(packet.NetworkLayer().NetworkFlow(), tcp, &context{
		CaptureInfo: packet.Metadata().CaptureInfo,
	})
	aMu.Unlock()

	// TODO: refactor and use a ticker model in a goroutine, similar to progress reporting
	if decoderconfig.Instance.FlushEvery > 0 {
		streamutils.Stats.Lock()
		doFlush := streamutils.Stats.Count%int64(decoderconfig.Instance.FlushEvery) == 0
		streamutils.Stats.Unlock()

		// flush connections in interval
		if doFlush {
			ref := packet.Metadata().CaptureInfo.Timestamp
			aMu.Lock()
			flushed, closed := assembler.FlushWithOptions(
				reassembly.FlushOptions{
					T:  ref.Add(-decoderconfig.Instance.ClosePendingTimeOut),
					TC: ref.Add(-decoderconfig.Instance.CloseInactiveTimeOut),
				},
			)
			aMu.Unlock()
			reassemblyLog.Debug("forced flush",
				zap.Int("flushed", flushed),
				zap.Int("closed", closed),
				zap.Time("ref", ref),
			)
		}
	}
}

// assembleWithContextTimeout is a function that times out with a log message after a specified interval
// when the stream reassembly gets stuck
// used for debugging.
//goland:noinspection GoUnusedFunction
func assembleWithContextTimeout(packet gopacket.Packet, assembler *reassembly.Assembler, tcp *layers.TCP) {
	done := make(chan bool, 1)

	go func() {
		aMu.Lock()
		assembler.AssembleWithContext(packet.NetworkLayer().NetworkFlow(), tcp, &context{
			CaptureInfo: packet.Metadata().CaptureInfo,
		})
		aMu.Unlock()
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

// CleanupReassembly will shutdown the reassembly.
func CleanupReassembly(wait bool, assemblers []*reassembly.Assembler) {
	decoderconfig.Instance.Lock()
	if decoderconfig.Instance.Debug {
		reassemblyLog.Info("streamPool:")
		reassemblyLog.Sugar().Info(StreamFactory.StreamPool.DumpString())
	}
	decoderconfig.Instance.Unlock()

	// wait for stream reassembly to finish
	if decoderconfig.Instance.WaitForConnections || wait {

		reassemblyLog.Info("waiting for last streams to finish processing...")

		// wait for remaining connections to finish processing
		// will wait forever if there are streams that are never shutdown via FIN/RST
		select {
		case <-waitForConns():
		case <-time.After(defaults.ReassemblyTimeout):
			if !decoderconfig.Instance.Quiet {
				reassemblyLog.Info(" timeout after", zap.Duration("reassembly_timeout", defaults.ReassemblyTimeout))
			}
		}

		if !decoderconfig.Instance.Quiet {
			fmt.Println("\nprocessing last TCP streams")
		}

		// flush assemblers
		// must be done after waiting for connections or there might be data loss
		for i, a := range assemblers {
			reassemblyLog.Info("flushing tcp assembler",
				zap.Int("current", i+1),
				zap.Int("numAssemblers", len(assemblers)),
			)

			if i == 0 && (!decoderconfig.Instance.Quiet || decoderconfig.Instance.PrintProgress) {
				// only display progress bar for the first flush, since all following ones will be instant.
				reassemblyLog.Info("assembler flush", zap.Int("closed", a.FlushAllProgress()))
			} else {
				reassemblyLog.Info("assembler flush", zap.Int("closed", a.FlushAll()))
			}
		}

		StreamFactory.Lock()
		numTotal := len(StreamFactory.streamReaders)
		StreamFactory.Unlock()

		startFlush := time.Now()
		reassemblyLog.Info("flushTCPStreams", zap.Int("numTotal", numTotal))
		flushTCPStreams(numTotal)
		reassemblyLog.Info("flushTCPStreams DONE", zap.String("delta", time.Since(startFlush).String()))

		udp.FlushUDPStreams()
	}

	if dpi.IsEnabled() {
		// teardown DPI C libs
		dpi.Destroy()
	}

	// create a memory snapshot for debugging
	if decoderconfig.Instance.MemProfile != "" {
		f, err := os.Create(decoderconfig.Instance.MemProfile)
		if err != nil {
			log.Fatal(err)
		}

		if err = pprof.WriteHeapProfile(f); err != nil {
			log.Fatal("failed to write heap profile:", err)
		}

		if err = f.Close(); err != nil {
			log.Fatal("failed to close heap profile file:", err)
		}
	}

	// print stats if not quiet
	if !decoderconfig.Instance.Quiet {
		errorsMapMutex.Lock()
		streamutils.Stats.Lock()
		reassemblyLog.Info("HTTPDecoder stats",
			zap.Int64("packets", streamutils.Stats.Count),
			zap.Int64("bytes", streamutils.Stats.DataBytes),
			zap.Duration("duration", time.Since(start)),
			zap.Uint("numErrors", streamutils.Stats.NumErrors),
			zap.Int("len(errorsMap)", len(errorsMap)),
			zap.Int64("requests", streamutils.Stats.Requests),
			zap.Int64("responses", streamutils.Stats.Responses),
		)
		streamutils.Stats.Unlock()
		errorsMapMutex.Unlock()

		// print configuration
		// print configuration as table
		tui.Table(reassemblyLogFileHandle, []string{"Reassembly Setting", "Value"}, [][]string{
			{"FlushEvery", strconv.Itoa(decoderconfig.Instance.FlushEvery)},
			{"CloseInactiveTimeout", decoderconfig.Instance.CloseInactiveTimeOut.String()},
			{"ClosePendingTimeout", decoderconfig.Instance.ClosePendingTimeOut.String()},
			{"AllowMissingInit", strconv.FormatBool(decoderconfig.Instance.AllowMissingInit)},
			{"IgnoreFsmErr", strconv.FormatBool(decoderconfig.Instance.IgnoreFSMerr)},
			{"NoOptCheck", strconv.FormatBool(decoderconfig.Instance.NoOptCheck)},
			{"Checksum", strconv.FormatBool(decoderconfig.Instance.Checksum)},
			{"DefragIPv4", strconv.FormatBool(decoderconfig.Instance.DefragIPv4)},
			{"WriteIncomplete", strconv.FormatBool(decoderconfig.Instance.WriteIncomplete)},
		})

		printProgress(1, 1)

		streamutils.Stats.Lock()

		var rows [][]string
		if decoderconfig.Instance.DefragIPv4 {
			rows = append(rows, []string{"IPv4 defragmentation", strconv.FormatInt(streamutils.Stats.IPdefrag, 10)})
		}

		rows = append(rows,
			[]string{"missed bytes", strconv.FormatInt(streamutils.Stats.MissedBytes, 10)},
			[]string{"total packets", strconv.FormatInt(streamutils.Stats.Pkt, 10)},
			[]string{"rejected FSM", strconv.FormatInt(streamutils.Stats.RejectFsm, 10)},
			[]string{"rejected Options", strconv.FormatInt(streamutils.Stats.RejectOpt, 10)},
			[]string{"reassembled bytes", strconv.FormatInt(streamutils.Stats.Sz, 10)},
			[]string{"total TCP bytes", strconv.FormatInt(streamutils.Stats.Totalsz, 10)},
			[]string{"connection rejected FSM", strconv.FormatInt(streamutils.Stats.RejectConnFsm, 10)},
			[]string{"reassembled chunks", strconv.FormatInt(streamutils.Stats.Reassembled, 10)},
			[]string{"out-of-order packets", strconv.FormatInt(streamutils.Stats.OutOfOrderPackets, 10)},
			[]string{"out-of-order bytes", strconv.FormatInt(streamutils.Stats.OutOfOrderBytes, 10)},
			[]string{"biggest-chunk packets", strconv.FormatInt(streamutils.Stats.BiggestChunkPackets, 10)},
			[]string{"biggest-chunk bytes", strconv.FormatInt(streamutils.Stats.BiggestChunkBytes, 10)},
			[]string{"overlap packets", strconv.FormatInt(streamutils.Stats.OverlapPackets, 10)},
			[]string{"overlap bytes", strconv.FormatInt(streamutils.Stats.OverlapBytes, 10)},
			[]string{"saved TCP connections", strconv.FormatInt(streamutils.Stats.SavedTCPConnections, 10)},
			[]string{"saved UDP conversations", strconv.FormatInt(streamutils.Stats.SavedUDPConnections, 10)},
			[]string{"numSoftware", strconv.FormatInt(streamutils.Stats.NumSoftware, 10)},
			[]string{"numServices", strconv.FormatInt(streamutils.Stats.NumServices, 10)},
		)
		streamutils.Stats.Unlock()

		tui.Table(reassemblyLogFileHandle, []string{"TCP Stat", "Value"}, rows)

		errorsMapMutex.Lock()
		streamutils.Stats.Lock()
		if streamutils.Stats.NumErrors != 0 {
			rows = [][]string{}
			for e := range errorsMap {
				rows = append(rows, []string{e, strconv.FormatUint(uint64(errorsMap[e]), 10)})
			}

			tui.Table(reassemblyLogFileHandle, []string{"Error Subject", "Count"}, rows)
		}

		streamutils.Stats.Unlock()
		errorsMapMutex.Unlock()
	}
}

func waitForConns() chan struct{} {
	out := make(chan struct{})

	go func() {
		// WaitGoRoutines waits until the goroutines launched to process TCP streams are done
		// this will block forever if there are streams that are never shutdown (via RST or FIN flags)
		StreamFactory.waitGoRoutines()
		out <- struct{}{}
	}()

	return out
}

// sort the conversation fragments and fill the conversation buffers.
func (t *tcpConnection) sortAndMergeFragments() {
	t.Lock()
	if !t.wasMerged {

		// only do this once per connection
		t.wasMerged = true

		// concatenate both client and server data fragments
		t.merged = append(t.client.DataSlice(), t.server.DataSlice()...)

		// sort based on their timestamps
		sort.Sort(t.merged)
	}
	t.Unlock()
}

func printProgress(current, total int64) {
	if current%5 == 0 {
		utils.ClearLine()
		print("flushing... (" + progress(current, total) + ")")
	}
}

func progress(current, total int64) string {
	percent := (float64(current) / float64(total)) * 100
	return strconv.Itoa(int(percent)) + "%"
}
