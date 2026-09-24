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
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"reflect"
	"runtime/pprof"
	"strconv"
	"sync"
	"time"

	"github.com/gopacket/gopacket"

	"github.com/dreadl0ck/netcap/internal/table"
	"github.com/gopacket/gopacket/layers"
	"go.uber.org/zap"

	decoderconfig "github.com/dreadl0ck/netcap/internal/decoder/config"
	"github.com/dreadl0ck/netcap/internal/decoder/core"
	"github.com/dreadl0ck/netcap/internal/decoder/stream"
	"github.com/dreadl0ck/netcap/internal/decoder/stream/network"
	"github.com/dreadl0ck/netcap/internal/decoder/stream/udp"
	streamutils "github.com/dreadl0ck/netcap/internal/decoder/stream/utils"
	"github.com/dreadl0ck/netcap/internal/reassembly"
	"github.com/dreadl0ck/netcap/internal/utils"
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
	initStage uint8
	clientISN uint32
	serverISN uint32
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

	if accept && !tcp.RST && !tcp.FIN {
		// decode() reads initStage under the same lock
		t.Lock()

		switch t.initStage {
		case 0:
			if dir == reassembly.TCPDirClientToServer && tcp.SYN && !tcp.ACK {
				t.clientISN, t.initStage = tcp.Seq, 1
			}
		case 1:
			if dir == reassembly.TCPDirServerToClient && tcp.SYN && tcp.ACK && tcp.Ack == t.clientISN+1 {
				t.serverISN, t.initStage = tcp.Seq, 2
			}
		case 2:
			if dir == reassembly.TCPDirClientToServer && !tcp.SYN && tcp.ACK && tcp.Seq == t.clientISN+1 && tcp.Ack == t.serverISN+1 {
				t.initStage = 3
			}
		}

		t.Unlock()
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

	// Store before queueing so ReassemblyComplete sees every delivered fragment.
	if dir == reassembly.TCPDirClientToServer {
		streamData := &core.StreamData{
			RawData:            dataCpy,
			AssemblerContext:   ac,
			CaptureInformation: ac.GetCaptureInfo(),
			Dir:                dir,
		}
		t.client.StoreData(streamData)
		t.client.DataChan() <- streamData
	} else {
		streamData := &core.StreamData{
			RawData:            dataCpy,
			AssemblerContext:   ac,
			CaptureInformation: ac.GetCaptureInfo(),
			Dir:                dir,
		}
		t.server.StoreData(streamData)
		t.server.DataChan() <- streamData
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
	if skip != 0 {
		gap := &core.StreamData{AssemblerContext: ac, Dir: dir, SkippedBytes: skip}
		if skip > 0 {
			gap.SkippedBytes += length
		} // This delivery is discarded below.
		if dir == reassembly.TCPDirClientToServer {
			t.client.StoreData(gap)
		} else {
			t.server.StoreData(gap)
		}
	}

	if skip == -1 && decoderconfig.Instance.AllowMissingInit {
		// this is allowed
	} else if skip != 0 {
		// Missing bytes in stream: do not even try to parse it
		return
	}

	if length > 0 {
		sg.ForEach(func(data []byte, context reassembly.AssemblerContext) {
			if decoderconfig.Instance.HexDump {
				reassemblyLog.Debug("feeding stream reader",
					zap.String("data", hex.Dump(data)),
				)
			}

			t.feedData(dir, data, context)
		})
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

	clientSaved := false
	serverSaved := false
	if t.client != nil {
		clientSaved = t.client.Saved()
	}
	if t.server != nil {
		serverSaved = t.server.Saved()
	}

	reassemblyLog.Info("ReassemblyComplete called",
		zap.String("ident", t.ident),
		zap.String("reason", reason),
		zap.Bool("clientIsNil", t.client == nil),
		zap.Bool("clientSaved", clientSaved),
		zap.Bool("serverIsNil", t.server == nil),
		zap.Bool("serverSaved", serverSaved),
		zap.Int("mergedFragments", len(t.mergedFragments())),
	)

	ti := time.Now()

	// save data for the current stream
	if t.server != nil && !t.client.Saved() {
		t.client.MarkSaved()

		t.sortAndMergeFragments()

		merged := t.mergedFragments()

		reassemblyLog.Info("Processing client stream - will call decode()",
			zap.String("ident", t.ident),
			zap.Int("mergedFragments", len(merged)),
		)

		// cache endpoint strings to avoid repeated conversions
		clientIP := t.client.Network().Src().String()
		serverIP := t.client.Network().Dst().String()
		clientPort := utils.DecodePort(t.client.Transport().Src().Raw())
		serverPort := utils.DecodePort(t.client.Transport().Dst().Raw())

		// save the full conversation to disk if enabled
		// Calculate Community ID once for use by harvesters
		communityID := streamutils.CalcCommunityIDTCP(
			clientIP,
			serverIP,
			uint16(clientPort),
			uint16(serverPort),
		)
		err := streamutils.SaveConversation("TCP", merged, t.client.Ident(), t.client.FirstPacket(), t.client.Transport(), communityID)
		if err != nil {
			reassemblyLog.Error("failed to save stream", zap.Error(err), zap.String("ident", t.client.Ident()))
		}
		tcpStreamProcessingTime.WithLabelValues(reassembly.TCPDirClientToServer.String()).Set(float64(time.Since(ti).Nanoseconds()))

		// decode the actual conversation.
		// this needs to be invoked only once, and since ReassemblyComplete is invoked for each side of the connection
		// decode should be called either when processing the client or the server stream
		t.decode()
	} else {
		reassemblyLog.Debug("Skipping decode() call",
			zap.String("ident", t.ident),
			zap.Bool("serverIsNil", t.server == nil),
			zap.Bool("clientAlreadySaved", t.client != nil && t.client.Saved()),
		)
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
	cr, sr := t.client.DataSlice().FirstNonEmpty(), t.server.DataSlice().FirstNonEmpty()

	// cache endpoint strings to avoid repeated conversions
	cIP := t.client.Network().Src().String()
	sIP := t.client.Network().Dst().String()
	cPort := utils.DecodePort(t.client.Transport().Src().Raw())
	sPort := utils.DecodePort(t.client.Transport().Dst().Raw())

	conv := &core.ConversationInfo{
		Data:                 t.merged,
		ClientData:           t.client.DataSlice(),
		ServerData:           t.server.DataSlice(),
		Ident:                t.ident,
		FirstClientPacket:    t.client.FirstPacket(),
		FirstServerPacket:    t.server.FirstPacket(),
		ClientIP:             cIP,
		ServerIP:             sIP,
		ClientPort:           cPort,
		ServerPort:           sPort,
		CommunityID:          streamutils.CalcCommunityIDTCP(cIP, sIP, uint16(cPort), uint16(sPort)),
		TCPHandshakeComplete: t.initStage == 3,
	}

	// Use the client's destination port (= server's listening port) for decoder matching
	// NOT the server's destination port (which would be the client's ephemeral port)
	serverPort := utils.DecodePort(t.client.Transport().Dst().Raw())
	reassemblyLog.Debug("TCP decode() - attempting decoder selection",
		zap.String("ident", t.ident),
		zap.Int("serverPort", int(serverPort)),
		zap.Int("clientDataLen", len(cr)),
		zap.Int("serverDataLen", len(sr)),
		zap.Int("mergedFragments", len(t.merged)),
	)

	// The fallback scan sees a whole direction concatenated, because a
	// length-prefixed protocol cannot be recognized from its first fragment
	// alone. The port pass sees only that fragment.
	sel, found := stream.SelectDecoder(&stream.SelectionInput{
		Transport:    core.TCP,
		ServerPort:   serverPort,
		PortClient:   cr,
		PortServer:   sr,
		ScanClient:   t.client.DataSlice().Bytes(),
		ScanServer:   t.server.DataSlice().Bytes(),
		Conversation: conv,
	})

	if found {
		t.decoder = sel.Decoder

		reassemblyLog.Info("Stream decoder selected",
			zap.String("ident", t.ident),
			zap.String("decoder", sel.Name),
			zap.String("via", sel.Via),
			zap.Int("port", int(sel.Port)),
		)
	} else {
		reassemblyLog.Debug("No decoder matched",
			zap.String("ident", t.ident),
			zap.Int("serverPort", int(serverPort)),
			zap.Int("availableDecoders", len(stream.DefaultStreamDecoders)),
		)
	}

	// call the decoder if one was found
	if t.decoder != nil {
		ti := time.Now()
		decoderTypeName := reflect.TypeOf(t.decoder).String()

		reassemblyLog.Info("Calling decoder.Decode()",
			zap.String("ident", t.ident),
			zap.String("decoderType", decoderTypeName),
		)

		// call the associated decoder
		t.decoder.Decode()

		tcpStreamDecodeTime.WithLabelValues(decoderTypeName).Set(float64(time.Since(ti).Nanoseconds()))

		reassemblyLog.Info("Decoder.Decode() completed",
			zap.String("ident", t.ident),
			zap.Duration("duration", time.Since(ti)),
		)
	} else {
		reassemblyLog.Debug("No decoder selected for stream",
			zap.String("ident", t.ident),
			zap.Int("serverPort", int(serverPort)),
		)
	}
}

// ReassemblePacket takes care of submitting a TCP / UDP packet to the reassembly.
// The caller owns the assembler and serializes assembly and maintenance.
func ReassemblePacket(packet gopacket.Packet, assembler *reassembly.Assembler) {
	// DefragIPv4 is unsupported: retain fragments as network conversations,
	// never as partial TCP/UDP segments. Avoid decoding ordinary TCP payloads.
	switch ip := packet.NetworkLayer().(type) {
	case *layers.IPv4:
		if ip.FragOffset != 0 || ip.Flags&layers.IPv4MoreFragments != 0 {
			handleNetworkLayerPacket(packet)
			return
		}
	case *layers.IPv6:
		if ip.NextHeader != layers.IPProtocolTCP && ip.NextHeader != layers.IPProtocolUDP && packet.Layer(layers.LayerTypeIPv6Fragment) != nil {
			handleNetworkLayerPacket(packet)
			return
		}
	}

	// TODO: make transport layer reassembler configurable
	// prevent passing any non TCP packets in here
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {

		// handle UDP stream reconstruction
		udpLayer := packet.Layer(layers.LayerTypeUDP)
		if udpLayer != nil {
			udp.Streams.HandleUDP(packet, udpLayer)
			return
		}

		// handle network-layer-only protocols (ICMP, IGMP, GRE, etc.)
		// These packets have a network layer but no transport layer
		if nl := packet.NetworkLayer(); nl != nil {
			handleNetworkLayerPacket(packet)
		}

		return
	}

	// lock to sync with read on destroy
	streamutils.Stats.Lock()
	streamutils.Stats.Count++
	streamutils.Stats.DataBytes += int64(len(packet.Data()))
	streamutils.Stats.Unlock()

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

	assembler.AssembleWithContext(packet.NetworkLayer().NetworkFlow(), tcp, &context{
		CaptureInfo: packet.Metadata().CaptureInfo,
	})
}

// CleanupReassembly finalizes all pools after packet workers have joined.
// The wait argument is retained for callers; even forced shutdown must drain data.
func CleanupReassembly(_ bool, assemblers []*reassembly.Assembler) {
	decoderconfig.LockInstance()
	if decoderconfig.Instance.Debug {
		for i, a := range assemblers {
			reassemblyLog.Info("assembler", zap.Int("index", i), zap.String("state", a.Dump()))
		}
	}
	decoderconfig.UnlockInstance()
	StreamFactory.Lock()
	numTotal := len(StreamFactory.streamReaders)
	StreamFactory.Unlock()
	if !decoderconfig.Instance.Quiet && numTotal > 1 {
		fmt.Println("\nprocessing last TCP streams")
	}

	// Flush every private pool while reader channels can still receive data.
	for i, a := range assemblers {
		reassemblyLog.Info("flushing tcp assembler",
			zap.Int("current", i+1),
			zap.Int("numAssemblers", len(assemblers)),
		)

		if i == 0 && (!decoderconfig.Instance.Quiet || decoderconfig.Instance.PrintProgress) && numTotal > 1 {
			reassemblyLog.Info("assembler flush", zap.Int("closed", a.FlushAllProgress()))
		} else {
			reassemblyLog.Info("assembler flush", zap.Int("closed", a.FlushAll()))
		}
	}

	CloseStreamReaderChannelsAndWait()
	startFlush := time.Now()
	reassemblyLog.Info("flushTCPStreams", zap.Int("numTotal", numTotal))
	flushTCPStreams(numTotal)
	reassemblyLog.Info("flushTCPStreams DONE", zap.String("delta", time.Since(startFlush).String()))

	udp.FlushUDPStreams()
	network.FlushNetworkStreams()

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
		table.Render(reassemblyLogFileHandle, []string{"Reassembly Setting", "Value"}, [][]string{
			{"FlushEvery", strconv.Itoa(decoderconfig.Instance.FlushEvery)},
			{"CloseInactiveTimeout", decoderconfig.Instance.CloseInactiveTimeOut.String()},
			{"ClosePendingTimeout", decoderconfig.Instance.ClosePendingTimeOut.String()},
			{"AllowMissingInit", strconv.FormatBool(decoderconfig.Instance.AllowMissingInit)},
			{"IgnoreFsmErr", strconv.FormatBool(decoderconfig.Instance.IgnoreFSMerr)},
			{"NoOptCheck", strconv.FormatBool(decoderconfig.Instance.NoOptCheck)},
			{"Checksum", strconv.FormatBool(decoderconfig.Instance.Checksum)},
			{"DefragIPv4 (unsupported)", strconv.FormatBool(decoderconfig.Instance.DefragIPv4)},
			{"WriteIncomplete", strconv.FormatBool(decoderconfig.Instance.WriteIncomplete)},
		})

		printProgress(1, 1)

		streamutils.Stats.Lock()

		var rows [][]string
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

		table.Render(reassemblyLogFileHandle, []string{"TCP Stat", "Value"}, rows)

		errorsMapMutex.Lock()
		streamutils.Stats.Lock()
		if streamutils.Stats.NumErrors != 0 {
			rows = [][]string{}
			for e := range errorsMap {
				rows = append(rows, []string{e, strconv.FormatUint(uint64(errorsMap[e]), 10)})
			}

			table.Render(reassemblyLogFileHandle, []string{"Error Subject", "Count"}, rows)
		}

		streamutils.Stats.Unlock()
		errorsMapMutex.Unlock()
	}
}

// sort the conversation fragments and fill the conversation buffers.
// mergedFragments returns the merged fragment slice under the connection lock.
//
// The slice header is written by sortAndMergeFragments while a connection's
// reader goroutines may still be running, so reading t.merged directly from
// ReassemblyComplete was a race on the header itself even after the merged slice
// stopped sharing the readers' backing array. The returned slice is safe to use
// unlocked: sortAndMergeFragments allocates it, nothing appends to it
// afterwards, and the fragments it points at are immutable once fed.
func (t *tcpConnection) mergedFragments() core.DataFragments {
	t.Lock()
	defer t.Unlock()

	return t.merged
}

func (t *tcpConnection) sortAndMergeFragments() {
	t.Lock()
	if !t.wasMerged {

		// only do this once per connection
		t.wasMerged = true

		// Stable two-way merge by capture timestamp, so the two directions
		// interleave by time while each direction keeps its byte order.
		//
		// Sorting the concatenation instead corrupted the stream: a delivery
		// carries the packet that closed a hole followed by the earlier-captured
		// packets it had queued, so timestamps within one direction are not
		// monotonic, and reordering them scrambles every consumer that reads
		// conversation.Data as a byte stream.
		//
		// The result also has to own its memory. This was once written as
		// append(client, server...), which appends in place whenever the client
		// slice has spare capacity -- and it does, since StoreData grows it by
		// repeated append. The merged slice then shared the client reader's live
		// fragment array, so permuting it interleaved server fragments into
		// t.client.data (decode() picks the decoder from the first client
		// fragment) and it raced with the reader goroutine appending.
		//
		// The fragments themselves are shared, but a *core.StreamData's RawData
		// is written once in feedData and never mutated, so reading them is safe.
		t.merged = core.MergeByTimestamp(t.client.DataSlice(), t.server.DataSlice())
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

// handleNetworkLayerPacket processes packets that have a network layer but no transport layer
// These include ICMP, IGMP, GRE, and other network-layer protocols
func handleNetworkLayerPacket(packet gopacket.Packet) {
	nl := packet.NetworkLayer()
	if nl == nil {
		return
	}

	// Determine the protocol type and payload
	var protocol string
	var payload []byte

	// Check for ICMPv4
	if icmpv4Layer := packet.Layer(layers.LayerTypeICMPv4); icmpv4Layer != nil {
		protocol = "ICMPv4"
		icmp := icmpv4Layer.(*layers.ICMPv4)
		payload = icmp.Payload
	} else if icmpv6Layer := packet.Layer(layers.LayerTypeICMPv6); icmpv6Layer != nil {
		// Check for ICMPv6
		protocol = "ICMPv6"
		icmp := icmpv6Layer.(*layers.ICMPv6)
		payload = icmp.Payload
	} else if igmpLayer := packet.Layer(layers.LayerTypeIGMP); igmpLayer != nil {
		// Check for IGMP
		protocol = "IGMP"
		payload = igmpLayer.LayerPayload()
	} else if greLayer := packet.Layer(layers.LayerTypeGRE); greLayer != nil {
		// Check for GRE
		protocol = "GRE"
		payload = greLayer.LayerPayload()
	} else if ipv4Layer := packet.Layer(layers.LayerTypeIPv4); ipv4Layer != nil {
		// Fallback to IPv4 payload for unknown protocol
		ipv4 := ipv4Layer.(*layers.IPv4)
		protocol = ipv4.Protocol.String()
		payload = ipv4.Payload
	} else if ipv6Layer := packet.Layer(layers.LayerTypeIPv6); ipv6Layer != nil {
		// Fallback to IPv6 payload
		ipv6 := ipv6Layer.(*layers.IPv6)
		protocol = ipv6.NextHeader.String()
		payload = ipv6.Payload
	} else {
		// Unknown network layer packet
		return
	}

	// Handle the packet in the network stream pool
	if len(payload) > 0 || protocol != "" {
		network.Streams.HandleNetworkPacket(packet, payload, protocol)
	}
}
