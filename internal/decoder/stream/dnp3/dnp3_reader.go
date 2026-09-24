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

package dnp3

import (
	"encoding/binary"
	"sync/atomic"

	"github.com/gopacket/gopacket"
	"go.uber.org/zap"

	"github.com/dreadl0ck/netcap/internal/decoder/core"
	"github.com/dreadl0ck/netcap/internal/reassembly"
	"github.com/dreadl0ck/netcap/types"
)

// Parse status values, matching the Modbus decoder.
const (
	statusValid       = "valid"
	statusMalformed   = "malformed"
	statusUnsupported = "unsupported"
	statusLost        = "lost"
)

type dnp3Reader struct {
	conversation *core.ConversationInfo
}

// New returns a new DNP3 reader.
func (d *dnp3Reader) New(conversation *core.ConversationInfo) core.StreamDecoderInterface {
	return &dnp3Reader{conversation: conversation}
}

// Decode parses DNP3 frames from the stream.
func (d *dnp3Reader) Decode() {
	if Decoder.Writer == nil {
		dnp3Log.Error("DNP3 Decoder.Writer is nil")

		return
	}

	d.frameConversation(func(msg *types.DNP3) {
		if err := Decoder.Writer.Write(msg); err != nil {
			dnp3Log.Error("failed to write DNP3 record", zap.Error(err))

			return
		}

		atomic.AddInt64(&Decoder.NumRecordsWritten, 1)
	})
}

// frameConversation frames each direction independently.
//
// Both directions share a TCP connection but not a frame boundary, so decoding
// them from one merged buffer interleaves them and destroys the framing. It
// also loses the direction itself: an outstation's response recorded with the
// master's address cannot be told from a command.
func (d *dnp3Reader) frameConversation(emit func(*types.DNP3)) {
	// Client and server are only known when the handshake was observed; a
	// midstream capture may have the assignment reversed. Without that, the
	// DIR bit cannot be checked against the network direction.
	oriented := d.conversation.TCPHandshakeComplete

	for _, fragments := range []core.DataFragments{d.conversation.ClientData, d.conversation.ServerData} {
		for _, fragment := range fragments {
			if data, ok := fragment.(*core.StreamData); !ok || data.SkippedBytes == -1 {
				oriented = false
			}
		}
	}

	clientData, serverData := d.conversation.ClientData, d.conversation.ServerData
	if len(clientData) == 0 && len(serverData) == 0 {
		// Callers that supply only the merged view still get framed output, but
		// the direction is unknown so the DIR bit is not cross-checked.
		clientData = d.conversation.Data
		oriented = false
	}

	// Correlation needs both directions in hand, so records are collected and
	// released together. The fragments they were decoded from are already held
	// for the whole conversation, so this does not change what is retained.
	var client, server []*types.DNP3

	d.frameDirection(clientData, false, oriented, func(r *types.DNP3) { client = append(client, r) })
	d.frameDirection(serverData, true, oriented, func(r *types.DNP3) { server = append(server, r) })

	correlate(client, server)

	for _, r := range client {
		emit(r)
	}

	for _, r := range server {
		emit(r)
	}
}

// timeMark records where a fragment's bytes begin in the working buffer, so a
// frame is timestamped from the packet that carried its first byte rather than
// from the start of the conversation.
//
// DNP3 masters hold a connection open for days. Stamping every frame with the
// conversation's first packet collapses a whole polling session to one instant,
// which makes a maintenance window unanswerable.
type timeMark struct {
	offset int
	ts     int64
}

type directionState struct {
	buf    []byte
	marks  []timeMark
	server bool
	loss   lossEvent
}

// append adds a fragment's bytes and records their capture time.
func (s *directionState) append(b []byte, ts int64) {
	s.marks = append(s.marks, timeMark{offset: len(s.buf), ts: ts})
	s.buf = append(s.buf, b...)
}

// discard drops n bytes from the front and rebases the time marks.
func (s *directionState) discard(n int) {
	if n <= 0 {
		return
	}

	if n >= len(s.buf) {
		s.buf, s.marks = s.buf[:0], s.marks[:0]

		return
	}

	s.buf = s.buf[n:]

	kept := s.marks[:0]

	for _, m := range s.marks {
		m.offset -= n
		if m.offset <= 0 {
			m.offset = 0

			if len(kept) > 0 {
				kept = kept[:len(kept)-1]
			}
		}

		kept = append(kept, m)
	}

	s.marks = kept
}

// timestampAt returns the capture time of the fragment covering offset.
func (s *directionState) timestamp(offset int) int64 {
	ts := int64(0)

	for _, m := range s.marks {
		if m.offset > offset {
			break
		}

		ts = m.ts
	}

	return ts
}

// lossEvent accumulates one coverage gap so that a direction which stopped
// producing evidence emits exactly one marker, not one per fragment.
type lossEvent struct {
	open      bool
	unknown   bool
	bytes     int64
	timestamp int64
	reason    string
}

func (l *lossEvent) note(bytes, timestamp int64, reason string) {
	if !l.open {
		l.open, l.timestamp, l.reason = true, timestamp, reason
	}

	if bytes < 0 {
		l.unknown = true

		return
	}

	l.bytes += bytes
}

func (l *lossEvent) flush(emit func(bytes, timestamp int64, reason string)) {
	if !l.open {
		return
	}

	bytes, timestamp, reason := l.bytes, l.timestamp, l.reason
	if l.unknown {
		bytes = -1
	}

	*l = lossEvent{}

	emit(bytes, timestamp, reason)
}

// frameDirection walks one direction of the conversation.
func (d *dnp3Reader) frameDirection(fragments core.DataFragments, server, oriented bool, emit func(*types.DNP3)) {
	if len(fragments) == 0 {
		return
	}

	state := &directionState{server: server, buf: make([]byte, 0, maxFrameLen)}

	emitLoss := func(bytes, timestamp int64, reason string) {
		emit(d.lostRecord(server, timestamp, bytes, reason))
	}

	for _, fragment := range fragments {
		data, ok := fragment.(*core.StreamData)
		if !ok {
			continue
		}

		if data.SkippedBytes != 0 {
			// Framing cannot survive a gap: the bytes buffered before it belong
			// to a frame whose remainder was destroyed.
			if len(state.buf) > 0 {
				state.loss.note(int64(len(state.buf)), state.timestamp(0), "unusable fragment")
				state.discard(len(state.buf))
			}

			state.loss.note(int64(data.SkippedBytes), fragmentTimestamp(data), "capture gap")
		}

		raw := data.Raw()
		if len(raw) == 0 {
			continue
		}

		state.append(raw, fragmentTimestamp(data))
		d.consume(state, oriented, emit, emitLoss)
	}

	// Trailing bytes that never completed a frame are unobserved, not absent.
	if len(state.buf) > 0 {
		state.loss.note(int64(len(state.buf)), state.timestamp(0), "truncated frame")
	}

	state.loss.flush(emitLoss)
}

// consume extracts every complete frame currently buffered.
func (d *dnp3Reader) consume(state *directionState, oriented bool, emit func(*types.DNP3), emitLoss func(bytes, timestamp int64, reason string)) {
	scan := 0

	for {
		start := frameStart(state.buf, scan)
		if start < 0 {
			// Keep a trailing 0x05 in case the pair straddles two fragments.
			keep := 0
			if n := len(state.buf); n > 0 && state.buf[n-1] == startByte1 {
				keep = 1
			}

			if drop := len(state.buf) - keep; drop > 0 {
				state.loss.note(int64(drop), state.timestamp(0), "unframed bytes discarded")
				state.discard(drop)
			}

			return
		}

		if len(state.buf)-start < linkHeaderLen {
			// Need more bytes before the header can be checked.
			if start > 0 {
				state.loss.note(int64(start), state.timestamp(0), "unframed bytes discarded")
				state.discard(start)
			}

			return
		}

		header := state.buf[start : start+linkHeaderLen]
		if !crcValid(header[:linkHeaderLen-2], header[linkHeaderLen-2:]) {
			// Two matching bytes inside a payload, not a frame.
			scan = start + 1

			continue
		}

		size := frameLen(header[2])
		if size < 0 {
			// Header authenticates but LENGTH is below the protocol minimum.
			// Report it: a master parsing this is the input the outstation is
			// trusted to supply.
			ts := state.timestamp(start)
			state.loss.flush(emitLoss)
			emit(d.malformedRecord(header, ts, state.server, oriented, "length below minimum"))
			state.discard(start + linkHeaderLen)

			scan = 0

			continue
		}

		if len(state.buf)-start < size {
			if start > 0 {
				state.loss.note(int64(start), state.timestamp(0), "unframed bytes discarded")
				state.discard(start)
			}

			return
		}

		if start > 0 {
			state.loss.note(int64(start), state.timestamp(0), "unframed bytes discarded")
		}

		ts := state.timestamp(start)
		frame := state.buf[start : start+size]

		// A marker stays ordered ahead of the record that ended the loss.
		state.loss.flush(emitLoss)
		emit(d.parseFrame(frame, ts, state.server, oriented))
		state.discard(start + size)

		scan = 0
	}
}

// streamFragment is the subset of the unexported core fragment interface the
// framer needs; it is restated here because core does not export it.
type streamFragment interface {
	CaptureInfo() gopacket.CaptureInfo
	Context() reassembly.AssemblerContext
	Raw() []byte
}

// fragmentTimestamp prefers the assembler context, which carries the capture
// time of the packet that closed a hole rather than of the fragment page.
func fragmentTimestamp(f streamFragment) int64 {
	if f.Context() != nil {
		return f.Context().GetCaptureInfo().Timestamp.UnixNano()
	}

	return f.CaptureInfo().Timestamp.UnixNano()
}

// attribute fills in the endpoints for a direction. A response carries the
// outstation as SrcIP.
func (d *dnp3Reader) attribute(msg *types.DNP3, server bool, timestamp int64) {
	msg.Timestamp = timestamp
	msg.CommunityID = d.conversation.CommunityID

	if server {
		msg.SrcIP, msg.DstIP = d.conversation.ServerIP, d.conversation.ClientIP
		msg.SrcPort, msg.DstPort = d.conversation.ServerPort, d.conversation.ClientPort

		return
	}

	msg.SrcIP, msg.DstIP = d.conversation.ClientIP, d.conversation.ServerIP
	msg.SrcPort, msg.DstPort = d.conversation.ClientPort, d.conversation.ServerPort
}

// lostRecord marks a direction that stopped producing evidence, so an empty
// hunt result can be told apart from a truncated capture.
func (d *dnp3Reader) lostRecord(server bool, timestamp, lost int64, reason string) *types.DNP3 {
	msg := &types.DNP3{
		ParseStatus:       statusLost,
		ParseError:        reason,
		LostBytes:         lost,
		CorrelationStatus: corrNotApplicable,
	}
	d.attribute(msg, server, timestamp)

	return msg
}

// linkHeader fills in the data link layer fields shared by every frame.
func (d *dnp3Reader) linkHeader(msg *types.DNP3, header []byte, server, oriented bool) {
	control := header[3]

	msg.Length = int32(header[2])
	msg.Control = int32(control)
	msg.IsMaster = control&0x80 != 0
	msg.IsRequest = control&0x40 != 0
	msg.LinkFCB = control&0x20 != 0
	msg.HeaderCRCValid = true

	if msg.IsRequest {
		msg.LinkFCV = control&0x10 != 0
	} else {
		msg.LinkDFC = control&0x10 != 0
	}

	msg.LinkFunctionCode = int32(control & 0x0F)
	msg.LinkFunctionCodeName = linkFunctionName(control&0x0F, msg.IsRequest)

	msg.Destination = int32(binary.LittleEndian.Uint16(header[4:6]))
	msg.Source = int32(binary.LittleEndian.Uint16(header[6:8]))

	msg.IsBroadcast = msg.Destination >= broadcastNoConfirm
	msg.IsSelfAddress = msg.Destination == selfAddress

	// The outstation listens, so the server side is the outstation and the DIR
	// bit should say so. A disagreement means the link address and the IP are
	// telling different stories.
	if oriented {
		msg.DirectionMismatch = msg.IsMaster == server
	}
}

func (d *dnp3Reader) malformedRecord(header []byte, ts int64, server, oriented bool, reason string) *types.DNP3 {
	msg := &types.DNP3{
		ParseStatus:       statusMalformed,
		ParseError:        reason,
		CorrelationStatus: corrNotApplicable,
	}
	d.attribute(msg, server, ts)
	d.linkHeader(msg, header, server, oriented)

	return msg
}

// parseFrame decodes one CRC-validated frame.
func (d *dnp3Reader) parseFrame(frame []byte, ts int64, server, oriented bool) *types.DNP3 {
	msg := &types.DNP3{ParseStatus: statusValid, CorrelationStatus: corrNotApplicable}
	d.attribute(msg, server, ts)
	d.linkHeader(msg, frame[:linkHeaderLen], server, oriented)

	user := userDataLen(frame[2])
	if user <= 0 {
		return msg
	}

	data, ok := extractUserData(frame[linkHeaderLen:], user)
	msg.BlockCRCValid = ok

	if !ok {
		// Corrupt user data. Report the framing and stop; decoding it would
		// publish values that were not sent.
		msg.ParseStatus, msg.ParseError = statusMalformed, "block CRC failed"

		return msg
	}

	if !carriesAPDU(frame[3]&0x0F, msg.IsRequest) {
		// Link control frames carry link state, not an application PDU.
		// Parsing one reads that state as a function code.
		msg.ParseStatus = statusUnsupported
		msg.ParseError = "link frame carries no application data"

		return msg
	}

	d.parseApplicationLayer(msg, data)

	return msg
}

func (d *dnp3Reader) parseApplicationLayer(msg *types.DNP3, data []byte) {
	if len(data) < 2 {
		msg.ParseStatus, msg.ParseError = statusMalformed, "truncated transport header"

		return
	}

	transport := data[0]
	msg.TransportSeq = int32(transport & 0x3F)
	msg.TransportFIN = transport&0x80 != 0
	msg.TransportFIR = transport&0x40 != 0

	if len(data) < 3 {
		msg.ParseStatus, msg.ParseError = statusMalformed, "truncated application header"

		return
	}

	appControl := data[1]
	msg.ApplicationControl = int32(appControl)
	msg.ApplicationSeq = int32(appControl & 0x0F)
	msg.ConfirmRequired = appControl&0x20 != 0
	msg.Unsolicited = appControl&0x10 != 0

	funcCode := int32(data[2])
	msg.FunctionCode = funcCode
	msg.FunctionCodeName = functionCodeName(funcCode)

	msg.IsCriticalFunction = criticalFunctions[funcCode]
	msg.IsConfigChange = configChangeFunctions[funcCode]
	msg.IsAuthentication = authenticationFunctions[funcCode]

	if _, known := functionCodeNames[funcCode]; !known {
		msg.ParseStatus, msg.ParseError = statusUnsupported, "unknown function code"

		return
	}

	objOffset := 3

	if funcCode == FuncResponse || funcCode == FuncUnsolicitedResponse {
		if len(data) < 5 {
			msg.ParseStatus, msg.ParseError = statusMalformed, "truncated internal indications"

			return
		}

		iin := binary.LittleEndian.Uint16(data[3:5])
		msg.InternalIndications = int32(iin)
		parseIIN(msg, iin)

		objOffset = 5
	}

	if len(data) <= objOffset {
		return
	}

	if !parseObjects(msg, data[objOffset:], carriesObjectData(funcCode)) {
		msg.ObjectsTruncated = true
	}
}

func parseIIN(msg *types.DNP3, iin uint16) {
	msg.IINBroadcast = iin&0x0001 != 0
	msg.IINClass1 = iin&0x0002 != 0
	msg.IINClass2 = iin&0x0004 != 0
	msg.IINClass3 = iin&0x0008 != 0
	msg.IINNeedTime = iin&0x0010 != 0
	msg.IINLocalControl = iin&0x0020 != 0
	msg.IINDeviceTrouble = iin&0x0040 != 0
	msg.IINDeviceRestart = iin&0x0080 != 0

	msg.IINNoFuncCodeSupport = iin&0x0100 != 0
	msg.IINObjectUnknown = iin&0x0200 != 0
	msg.IINParameterError = iin&0x0400 != 0
	msg.IINEventBufferOverflow = iin&0x0800 != 0
	msg.IINAlreadyExecuting = iin&0x1000 != 0
	msg.IINConfigCorrupt = iin&0x2000 != 0
}
