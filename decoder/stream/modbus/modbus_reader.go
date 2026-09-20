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

package modbus

import (
	"sync/atomic"

	"github.com/gopacket/gopacket"
	"go.uber.org/zap"

	decoderconfig "github.com/dreadl0ck/netcap/decoder/config"
	"github.com/dreadl0ck/netcap/decoder/core"
	"github.com/dreadl0ck/netcap/reassembly"
	"github.com/dreadl0ck/netcap/types"
)

// Modbus Function Codes (standard functions per Modbus Application Protocol Specification V1.1b3)
const (
	// Bit access - Single bits
	FuncReadCoils          = 0x01 // Read Coils (outputs)
	FuncReadDiscreteInputs = 0x02 // Read Discrete Inputs

	// Bit access - Multiple bits
	FuncWriteSingleCoil    = 0x05 // Write Single Coil
	FuncWriteMultipleCoils = 0x0F // Write Multiple Coils

	// 16-bit access - Single registers
	FuncReadHoldingRegisters = 0x03 // Read Holding Registers
	FuncReadInputRegisters   = 0x04 // Read Input Registers
	FuncWriteSingleRegister  = 0x06 // Write Single Register

	// 16-bit access - Multiple registers
	FuncWriteMultipleRegisters     = 0x10 // Write Multiple Registers
	FuncReadWriteMultipleRegisters = 0x17 // Read/Write Multiple Registers
	FuncMaskWriteRegister          = 0x16 // Mask Write Register
	FuncReadFIFOQueue              = 0x18 // Read FIFO Queue

	// File record access
	FuncReadFileRecord  = 0x14 // Read File Record
	FuncWriteFileRecord = 0x15 // Write File Record

	// Diagnostics
	FuncReadExceptionStatus   = 0x07 // Read Exception Status
	FuncDiagnostic            = 0x08 // Diagnostic
	FuncGetCommEventCounter   = 0x0B // Get Comm Event Counter
	FuncGetCommEventLog       = 0x0C // Get Comm Event Log
	FuncReportSlaveID         = 0x11 // Report Slave ID
	FuncEncapsulatedInterface = 0x2B // Encapsulated Interface Transport (includes Read Device Identification)

	// User-defined function codes (65-72, 100-110)
	// Vendor-specific, not parsed here
)

// Diagnostic sub-function codes
const (
	DiagReturnQueryData                = 0x00
	DiagRestartCommunications          = 0x01
	DiagReturnDiagnosticRegister       = 0x02
	DiagChangeASCIIInputDelimiter      = 0x03
	DiagForceListenOnlyMode            = 0x04
	DiagClearCountersAndDiagnosticReg  = 0x0A
	DiagReturnBusMessageCount          = 0x0B
	DiagReturnBusCommunicationError    = 0x0C
	DiagReturnBusExceptionErrorCount   = 0x0D
	DiagReturnSlaveMessageCount        = 0x0E
	DiagReturnSlaveNoResponseCount     = 0x0F
	DiagReturnSlaveNAKCount            = 0x10
	DiagReturnSlaveBusyCount           = 0x11
	DiagReturnBusCharacterOverrunCount = 0x12
	DiagClearOverrunCounter            = 0x14
)

// Exception codes
const (
	ExceptionIllegalFunction         = 0x01
	ExceptionIllegalDataAddress      = 0x02
	ExceptionIllegalDataValue        = 0x03
	ExceptionSlaveDeviceFailure      = 0x04
	ExceptionAcknowledge             = 0x05
	ExceptionSlaveDeviceBusy         = 0x06
	ExceptionNegativeAcknowledge     = 0x07
	ExceptionMemoryParityError       = 0x08
	ExceptionGatewayPathUnavailable  = 0x0A
	ExceptionGatewayTargetNoResponse = 0x0B
)

// Critical function codes that write to PLCs
var criticalFunctions = map[uint8]bool{
	FuncWriteSingleCoil:            true,
	FuncWriteSingleRegister:        true,
	FuncWriteMultipleCoils:         true,
	FuncWriteMultipleRegisters:     true,
	FuncReadWriteMultipleRegisters: true,
	FuncMaskWriteRegister:          true,
	FuncWriteFileRecord:            true,
}

// Diagnostic/maintenance functions
var diagnosticFunctions = map[uint8]bool{
	FuncReadExceptionStatus: true,
	FuncDiagnostic:          true,
	FuncGetCommEventCounter: true,
	FuncGetCommEventLog:     true,
	FuncReportSlaveID:       true,
}

type modbusReader struct {
	conversation *core.ConversationInfo
}

// New returns a new Modbus reader.
func (m *modbusReader) New(conversation *core.ConversationInfo) core.StreamDecoderInterface {
	return &modbusReader{
		conversation: conversation,
	}
}

// Decode parses Modbus TCP messages from the stream.
func (m *modbusReader) Decode() {
	if Decoder.Writer == nil {
		modbusLog.Error("Modbus Decoder.Writer is nil")
		return
	}

	m.frameConversation(func(msg *types.Modbus) {
		if decoderconfig.Instance.ExportMetrics {
			msg.Inc()
		}
		if err := Decoder.Writer.Write(msg); err != nil {
			modbusLog.Error("failed to write Modbus record", zap.Error(err))
		} else {
			atomic.AddInt64(&Decoder.NumRecordsWritten, 1)
		}
	})
}

// streamFragment is the subset of the unexported core fragment interface the
// framers need; it is restated here because core does not export it.
type streamFragment interface {
	Direction() reassembly.TCPFlowDirection
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

// attribute stamps a record with the endpoints of the direction it came from.
func (m *modbusReader) attribute(msg *types.Modbus, server bool, timestamp int64) {
	msg.Timestamp, msg.CommunityID = timestamp, m.conversation.CommunityID
	msg.SrcIP, msg.DstIP = m.conversation.ClientIP, m.conversation.ServerIP
	msg.SrcPort, msg.DstPort = int32(m.conversation.ClientPort), int32(m.conversation.ServerPort)
	if server {
		msg.SrcIP, msg.DstIP = msg.DstIP, msg.SrcIP
		msg.SrcPort, msg.DstPort = msg.DstPort, msg.SrcPort
	}
}

// lossEvent buffers a capture-loss marker for as long as the loss stays open,
// so that back to back gaps are reported once with the extent of the whole run
// rather than of its first gap. A contributing gap of unknown extent makes the
// total unknown.
type lossEvent struct {
	open      bool
	unknown   bool
	bytes     int64
	timestamp int64
	reason    string
}

// add opens the event on the first gap, keeping its timestamp and reason;
// later gaps only extend it.
func (l *lossEvent) add(skipped, timestamp int64, reason string) {
	if !l.open {
		*l = lossEvent{open: true, timestamp: timestamp, reason: reason}
	}
	if skipped < 0 {
		l.unknown = true
		return
	}
	l.bytes += skipped
}

// flush reports an open event and closes it. Callers flush when the direction
// decodes again, when it stops and at the end of the stream, so that a marker
// stays ordered ahead of the record that ended the loss.
func (l *lossEvent) flush(emit func(lost, timestamp int64, reason string)) {
	if !l.open {
		return
	}
	lost, timestamp, reason := l.bytes, l.timestamp, l.reason
	if l.unknown {
		lost = -1
	}
	*l = lossEvent{}
	emit(lost, timestamp, reason)
}

// lostRecord marks a direction that stopped producing evidence, so that an
// empty result can be told apart from a truncated one. lost carries the bytes
// reassembly reported missing over the whole loss event, -1 when that amount is
// unknown and 0 when the framing rather than the capture became unusable.
func (m *modbusReader) lostRecord(transport string, server bool, timestamp, lost int64, reason string) *types.Modbus {
	msg := &types.Modbus{
		Transport: transport, MessageRole: "unknown", ParseStatus: "lost", ParseError: reason,
		CorrelationStatus: "not_applicable", LostBytes: lost,
	}
	m.attribute(msg, server, timestamp)
	return msg
}

func (m *modbusReader) frameConversation(emit func(*types.Modbus)) {
	if IsRTUConversation(m.conversation) {
		m.frameRTU(emit)
		return
	}
	correlation := tcpCorrelation{pending: make(map[int32]pendingRequest)}
	// Client and server are only known when the handshake was observed; a
	// midstream capture may have the assignment flipped. Reassembly additionally
	// inserts an initial-loss marker when no SYN was observed, so inspect both
	// directions before emitting anything, including the legacy view.
	oriented := m.conversation.TCPHandshakeComplete
	for _, fragments := range []core.DataFragments{m.conversation.Data, m.conversation.ClientData, m.conversation.ServerData} {
		for _, fragment := range fragments {
			data, ok := fragment.(*core.StreamData)
			if !ok || data.SkippedBytes == -1 {
				oriented = false
			}
		}
	}
	type directionState struct {
		data      [mbapHeaderSize + maxPDUSize]byte
		n         int
		timestamp int64
		last      int64
		started   bool
		stopped   bool
		// resuming marks the first ADU after a gap as provisional: the resume
		// point is an ADU boundary only if the gap happened to end on one, and
		// an MBAP header is far too weak a signature to establish that alone.
		resuming bool
		// loss holds the marker until the loss ends, so one contiguous loss
		// event yields exactly one record covering its whole extent.
		loss lossEvent
	}
	var dirs [2]directionState
	lose := func(i int, skipped int64, reason string) {
		dirs[i].loss.add(skipped, dirs[i].last, reason)
	}
	flush := func(i int) {
		dirs[i].loss.flush(func(lost, timestamp int64, reason string) {
			emit(m.lostRecord("tcp", i == 1, timestamp, lost, reason))
		})
	}
	// A stopped direction can contribute no further gaps, so its event is over.
	stop := func(i int) {
		dirs[i].stopped = true
		flush(i)
	}
	feed := func(input streamFragment) {
		i := 0
		if input.Direction() == reassembly.TCPDirServerToClient {
			i = 1
		}
		f := &dirs[i]
		if f.stopped {
			return
		}
		f.last = fragmentTimestamp(input)
		fragment, ok := input.(*core.StreamData)
		if !ok {
			// Neither the missing byte count nor a frame start is known here.
			f.n = 0
			lose(i, -1, "unusable fragment")
			correlation.lose(f.last)
			stop(i)
			return
		}
		if fragment.SkippedBytes == -1 && !f.started && decoderconfig.Instance.AllowMissingInit {
			// A midstream start is as arbitrary as a post-gap resume point.
			f.resuming = true
		} else if fragment.SkippedBytes != 0 {
			f.n = 0
			lose(i, int64(fragment.SkippedBytes), "capture gap")
			correlation.lose(f.last)
			if fragment.SkippedBytes < 0 {
				// An unknown amount of loss leaves no known frame start.
				stop(i)
				return
			}
			// Bounded resynchronisation: the first byte after the gap is the
			// only resume point, and the ADU there stays provisional until it
			// parses.
			f.resuming = true
		}
		f.started = true
		data := fragment.Raw()
		for len(data) > 0 && !f.stopped {
			if f.n == 0 {
				f.timestamp = f.last
			}
			target := mbapHeaderSize + minPDUSize
			if f.n >= target {
				target = 6 + (int(f.data[4]) << 8) + int(f.data[5])
			}
			n := copy(f.data[f.n:target], data)
			f.n += n
			data = data[n:]
			if f.n < mbapHeaderSize+minPDUSize {
				continue
			}
			if !m.isModbusHeader(f.data[:f.n]) {
				// MBAP has no reliable sync marker; never scan a body for headers.
				f.n = 0
				lose(i, 0, "invalid MBAP header")
				correlation.lose(f.last)
				stop(i)
				continue
			}
			role := "unknown"
			if oriented {
				role = "request"
				if i == 1 {
					role = "response"
				}
			}
			msg, consumed := m.parseTCP(f.data[:f.n], role)
			if consumed == 0 {
				continue
			}
			if f.resuming {
				// Protocol ID zero and a plausible length occur throughout
				// ordinary register data, so only a parsable ADU shows the gap
				// ended on a boundary. Anything else is fabricated evidence and
				// must reach neither the output nor correlation.
				if msg.ParseStatus != "valid" {
					f.n = 0
					lose(i, 0, "unparsable ADU after capture gap")
					stop(i)
					continue
				}
				f.resuming = false
			}
			m.attribute(msg, i == 1, f.timestamp)
			correlation.observe(msg, i == 1)
			flush(i)
			emit(msg)
			f.n = 0
		}
	}
	for _, fragment := range m.orderedFragments() {
		feed(fragment)
	}
	// A direction ending inside an ADU stopped parsing; one ending on a frame
	// boundary did not, and must stay silent.
	for i := range dirs {
		if dirs[i].n > 0 && !dirs[i].stopped {
			lose(i, 0, "truncated ADU")
		}
		flush(i)
	}
}

// orderedFragments interleaves the per-direction views, falling back to the
// combined one. Like TLS, it merges heads without sorting either TCP sequence
// by capture time, which would reorder bytes within a direction.
func (m *modbusReader) orderedFragments() core.DataFragments {
	c, s := m.conversation.ClientData, m.conversation.ServerData
	if c == nil && s == nil {
		return m.conversation.Data
	}
	ordered := make(core.DataFragments, 0, len(c)+len(s))
	for len(c) > 0 || len(s) > 0 {
		useClient := len(s) == 0
		if len(c) > 0 && len(s) > 0 {
			useClient = fragmentTimestamp(s[0]) >= fragmentTimestamp(c[0])
		}
		if useClient {
			ordered, c = append(ordered, c[0]), c[1:]
			continue
		}
		ordered, s = append(ordered, s[0]), s[1:]
	}
	return ordered
}

// isModbusHeader checks if the data starts with a valid Modbus MBAP header.
func (m *modbusReader) isModbusHeader(data []byte) bool {
	if len(data) < mbapHeaderSize+minPDUSize {
		return false
	}

	// Protocol ID must be 0x0000
	protocolID := uint16(data[2])<<8 | uint16(data[3])
	if protocolID != modbusProtocolID {
		return false
	}

	// Validate length field
	length := uint16(data[4])<<8 | uint16(data[5])
	if length < 2 || length > 254 {
		return false
	}

	return true
}

// parseModbusMessage parses a Modbus TCP message and returns the record and bytes consumed.
func (m *modbusReader) parseModbusMessage(data []byte) (*types.Modbus, int) {
	return m.parseTCP(data, "unknown")
}

func (m *modbusReader) parseTCP(data []byte, role string) (*types.Modbus, int) {
	if !m.isModbusHeader(data) {
		return nil, 0
	}

	// Parse MBAP Header (7 bytes)
	transactionID := uint16(data[0])<<8 | uint16(data[1])
	protocolID := uint16(data[2])<<8 | uint16(data[3])
	length := uint16(data[4])<<8 | uint16(data[5])
	unitID := data[6]

	// Validate we have enough data
	totalLength := int(mbapHeaderSize) + int(length) - 1 // -1 because length includes unit ID
	if len(data) < totalLength {
		return nil, 0
	}

	msg := parsePDU(data[mbapHeaderSize:totalLength], role)
	msg.Transport = "tcp"
	msg.HasMBAP = true
	msg.TransactionID, msg.ProtocolID = int32(transactionID), int32(protocolID)
	msg.Length, msg.UnitID = int32(length), int32(unitID)

	// Include payload if configured
	if decoderconfig.Instance.IncludePayloads && totalLength > mbapHeaderSize {
		pduLen := totalLength - mbapHeaderSize
		if pduLen > 0 && len(data) >= mbapHeaderSize+pduLen {
			msg.Payload = make([]byte, pduLen)
			copy(msg.Payload, data[mbapHeaderSize:mbapHeaderSize+pduLen])
		}
	}

	return msg, totalLength
}

// GetFunctionCodeName returns the human-readable name for a Modbus function code.
func GetFunctionCodeName(code uint8) string {
	switch code {
	case FuncReadCoils:
		return "Read Coils"
	case FuncReadDiscreteInputs:
		return "Read Discrete Inputs"
	case FuncReadHoldingRegisters:
		return "Read Holding Registers"
	case FuncReadInputRegisters:
		return "Read Input Registers"
	case FuncWriteSingleCoil:
		return "Write Single Coil"
	case FuncWriteSingleRegister:
		return "Write Single Register"
	case FuncReadExceptionStatus:
		return "Read Exception Status"
	case FuncDiagnostic:
		return "Diagnostic"
	case FuncGetCommEventCounter:
		return "Get Comm Event Counter"
	case FuncGetCommEventLog:
		return "Get Comm Event Log"
	case FuncWriteMultipleCoils:
		return "Write Multiple Coils"
	case FuncWriteMultipleRegisters:
		return "Write Multiple Registers"
	case FuncReportSlaveID:
		return "Report Slave ID"
	case FuncReadFileRecord:
		return "Read File Record"
	case FuncWriteFileRecord:
		return "Write File Record"
	case FuncMaskWriteRegister:
		return "Mask Write Register"
	case FuncReadWriteMultipleRegisters:
		return "Read/Write Multiple Registers"
	case FuncReadFIFOQueue:
		return "Read FIFO Queue"
	case FuncEncapsulatedInterface:
		return "Encapsulated Interface Transport"
	default:
		if code >= 65 && code <= 72 {
			return "User Defined Function"
		}
		if code >= 100 && code <= 110 {
			return "User Defined Function"
		}
		return "Unknown"
	}
}

// GetExceptionCodeName returns the human-readable name for a Modbus exception code.
func GetExceptionCodeName(code uint8) string {
	switch code {
	case ExceptionIllegalFunction:
		return "Illegal Function"
	case ExceptionIllegalDataAddress:
		return "Illegal Data Address"
	case ExceptionIllegalDataValue:
		return "Illegal Data Value"
	case ExceptionSlaveDeviceFailure:
		return "Slave Device Failure"
	case ExceptionAcknowledge:
		return "Acknowledge"
	case ExceptionSlaveDeviceBusy:
		return "Slave Device Busy"
	case ExceptionNegativeAcknowledge:
		return "Negative Acknowledge"
	case ExceptionMemoryParityError:
		return "Memory Parity Error"
	case ExceptionGatewayPathUnavailable:
		return "Gateway Path Unavailable"
	case ExceptionGatewayTargetNoResponse:
		return "Gateway Target Device Failed to Respond"
	default:
		return "Unknown Exception"
	}
}

// IsCriticalFunction returns true if the function code is a write operation.
func IsCriticalFunction(code uint8) bool {
	return criticalFunctions[code]
}

// IsDiagnosticFunction returns true if the function code is a diagnostic operation.
func IsDiagnosticFunction(code uint8) bool {
	return diagnosticFunctions[code]
}
