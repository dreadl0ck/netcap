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

package s7comm

import (
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/decoder/core"
)

// newReader returns an s7commReader with a minimal conversation suitable for
// unit testing the byte-level parsers.
func newReader() *s7commReader {
	return &s7commReader{
		conversation: &core.ConversationInfo{
			FirstClientPacket: time.Unix(1700000000, 0),
			ClientIP:          "10.0.0.10",
			ServerIP:          "10.0.0.20",
			ClientPort:        50000,
			ServerPort:        102,
		},
	}
}

// tpkt wraps a COTP+S7 payload in a TPKT header (RFC 1006).
func tpkt(payload []byte) []byte {
	total := 4 + len(payload)
	frame := []byte{0x03, 0x00, byte(total >> 8), byte(total & 0xff)}
	return append(frame, payload...)
}

// cotpDT returns a COTP Data Transfer header (length 2, type 0xF0, EOT).
func cotpDT() []byte {
	return []byte{0x02, 0xf0, 0x80}
}

// s7Job builds a classic S7comm Job header (0x32/0x01) with the given
// parameter bytes and no data section.
func s7Job(param []byte) []byte {
	hdr := []byte{
		0x32, 0x01, // protocol id, ROSCTR = Job
		0x00, 0x00, // reserved
		0x00, 0x00, // pdu ref
		byte(len(param) >> 8), byte(len(param) & 0xff), // parameter length
		0x00, 0x00, // data length
	}
	return append(hdr, param...)
}

func TestCanDecodeS7Comm(t *testing.T) {
	readVarParam := []byte{0x04, 0x00} // ReadVar, item count 0
	valid := tpkt(append(cotpDT(), s7Job(readVarParam)...))

	tests := []struct {
		name string
		data []byte
		want bool
	}{
		{"valid s7comm read", valid, true},
		{"too short", []byte{0x03, 0x00, 0x00}, false},
		{"wrong tpkt version", append([]byte{0x04, 0x00, 0x00, 0x10}, make([]byte, 12)...), false},
		{"reserved nonzero", append([]byte{0x03, 0x01, 0x00, 0x10}, make([]byte, 12)...), false},
		{"not s7 payload", tpkt(append(cotpDT(), []byte{0x99, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}...)), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := canDecodeS7Comm(tt.data); got != tt.want {
				t.Errorf("canDecodeS7Comm() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseWriteVar(t *testing.T) {
	// WriteVar (0x05) with one S7-Any item addressing DB1.
	item := []byte{
		0x12, 0x0a, 0x10, // var spec, addr len 0x0A, syntax S7-Any
		0x02,       // transport size BYTE
		0x00, 0x04, // length 4
		0x00, 0x01, // DB number 1
		0x84,             // area = DB
		0x00, 0x00, 0x00, // start address
	}
	param := append([]byte{0x05, 0x01}, item...) // WriteVar, item count 1
	frame := tpkt(append(cotpDT(), s7Job(param)...))

	r := newReader()
	msg, consumed := r.parseTPKTMessage(frame)
	if msg == nil {
		t.Fatal("expected a parsed message")
	}
	if consumed != len(frame) {
		t.Errorf("consumed = %d, want %d", consumed, len(frame))
	}
	if msg.FunctionCode != S7FuncWriteVar {
		t.Errorf("FunctionCode = %#x, want %#x", msg.FunctionCode, S7FuncWriteVar)
	}
	if msg.FunctionName != "Write Var" {
		t.Errorf("FunctionName = %q, want Write Var", msg.FunctionName)
	}
	if !msg.IsCriticalOperation {
		t.Error("WriteVar must be flagged IsCriticalOperation")
	}
	if msg.ItemCount != 1 || len(msg.Items) != 1 {
		t.Fatalf("ItemCount = %d, items = %d, want 1/1", msg.ItemCount, len(msg.Items))
	}
	if msg.Items[0].Area != S7AreaDB {
		t.Errorf("item area = %#x, want DB %#x", msg.Items[0].Area, S7AreaDB)
	}
	if msg.Items[0].DBNumber != 1 {
		t.Errorf("item DB = %d, want 1", msg.Items[0].DBNumber)
	}
	// Src/Dst are set by Decode(), not parseTPKTMessage; verify header fields.
	if msg.MessageType != S7CommMsgTypeJobRequest {
		t.Errorf("MessageType = %d, want Job", msg.MessageType)
	}
}

func TestParseReadVar(t *testing.T) {
	param := []byte{0x04, 0x00} // ReadVar, no items
	frame := tpkt(append(cotpDT(), s7Job(param)...))

	msg, _ := newReader().parseTPKTMessage(frame)
	if msg == nil {
		t.Fatal("expected a parsed message")
	}
	if msg.FunctionCode != S7FuncReadVar {
		t.Errorf("FunctionCode = %#x, want ReadVar", msg.FunctionCode)
	}
	if msg.IsCriticalOperation {
		t.Error("ReadVar must NOT be flagged critical")
	}
}

func TestCriticalFunctionCodes(t *testing.T) {
	crit := []int{
		S7FuncWriteVar,
		S7FuncRequestDownload,
		S7FuncDownloadBlock,
		S7FuncDownloadEnded,
		S7FuncPIService,
		S7FuncPLCStop,
	}
	for _, fc := range crit {
		param := []byte{byte(fc), 0x00}
		frame := tpkt(append(cotpDT(), s7Job(param)...))
		msg, _ := newReader().parseTPKTMessage(frame)
		if msg == nil {
			t.Fatalf("fc %#x: nil message", fc)
		}
		if !msg.IsCriticalOperation {
			t.Errorf("fc %#x (%s) should be critical", fc, msg.FunctionName)
		}
	}
}

func TestParseAckDataErrorClass(t *testing.T) {
	// Ack-Data (0x03) header carries error class/code after the base header.
	// Error class 0x00 = completed successfully.
	hdr := []byte{
		0x32, 0x03, // protocol id, ROSCTR = Ack-Data
		0x00, 0x00, // reserved
		0x00, 0x00, // pdu ref
		0x00, 0x02, // parameter length 2
		0x00, 0x00, // data length
		0x00, 0x00, // error class 0x00, error code 0x00
		0x05, 0x00, // param: WriteVar, item count 0
	}
	frame := tpkt(append(cotpDT(), hdr...))

	msg, _ := newReader().parseTPKTMessage(frame)
	if msg == nil {
		t.Fatal("expected a parsed message")
	}
	if msg.MessageType != S7CommMsgTypeAckData {
		t.Errorf("MessageType = %d, want Ack-Data", msg.MessageType)
	}
	if msg.ErrorClass != 0 {
		t.Errorf("ErrorClass = %d, want 0", msg.ErrorClass)
	}
	if msg.ErrorName != "No error" {
		t.Errorf("ErrorName = %q, want No error", msg.ErrorName)
	}
	if msg.FunctionCode != S7FuncWriteVar {
		t.Errorf("FunctionCode = %#x, want WriteVar", msg.FunctionCode)
	}
}

func TestParseCOTPConnectionRequest(t *testing.T) {
	// COTP Connection Request (0xE0). The length indicator counts the header
	// bytes following it (dest ref + src ref + class = 6).
	cr := []byte{
		0x06,       // length indicator
		0xe0,       // CR
		0x00, 0x00, // dest ref
		0x00, 0x01, // src ref
		0x00, // class/options
	}
	frame := tpkt(cr)

	msg, _ := newReader().parseTPKTMessage(frame)
	if msg == nil {
		t.Fatal("expected a parsed message")
	}
	if msg.COTPPDUTypeName != "CR (Connection Request)" {
		t.Errorf("COTPPDUTypeName = %q", msg.COTPPDUTypeName)
	}
	if msg.COTPSrcRef != 1 {
		t.Errorf("COTPSrcRef = %d, want 1", msg.COTPSrcRef)
	}
}

func TestParsePIServiceRestartNaming(t *testing.T) {
	// PI service (0x28) carrying a cold-restart token "P_PROGRAM".
	token := []byte("P_PROGRAM")
	param := append([]byte{0x28, 0x00}, token...)
	frame := tpkt(append(cotpDT(), s7Job(param)...))

	msg, _ := newReader().parseTPKTMessage(frame)
	if msg == nil {
		t.Fatal("expected a parsed message")
	}
	if !msg.IsCriticalOperation {
		t.Error("PI service must be critical")
	}
	if msg.SubFunctionName != "Cold Restart (P_PROGRAM)" {
		t.Errorf("SubFunctionName = %q, want Cold Restart (P_PROGRAM)", msg.SubFunctionName)
	}
}

func TestParseS7CommPlusShallow(t *testing.T) {
	// S7CommPlus (0x72) v1, data length 0x0010, opcode 0x31 (Request).
	// parseS7Comm requires at least 10 bytes before dispatching.
	plus := []byte{0x72, 0x01, 0x00, 0x10, 0x31, 0x00, 0x04, 0x00, 0x00, 0x00}
	frame := tpkt(append(cotpDT(), plus...))

	msg, _ := newReader().parseTPKTMessage(frame)
	if msg == nil {
		t.Fatal("expected a parsed message")
	}
	if msg.ProtocolId != s7commPlusProtocolID {
		t.Errorf("ProtocolId = %#x, want S7CommPlus", msg.ProtocolId)
	}
	if !msg.IsSecurityRelevant {
		t.Error("S7CommPlus must be flagged IsSecurityRelevant")
	}
	if !msg.PayloadObscured {
		t.Error("S7CommPlus payload must be flagged obscured (function code undeterminable)")
	}
	if msg.S7PlusOpcode != s7PlusOpcodeRequest {
		t.Errorf("S7PlusOpcode = %#x, want Request", msg.S7PlusOpcode)
	}
	if msg.S7PlusOpcodeName != "Request" {
		t.Errorf("S7PlusOpcodeName = %q, want Request", msg.S7PlusOpcodeName)
	}
	if msg.DataLength != 0x10 {
		t.Errorf("DataLength = %d, want 16", msg.DataLength)
	}
}

func TestClassicS7CommNotObscured(t *testing.T) {
	// Classic S7comm (0x32) must NOT be flagged as obscured.
	param := []byte{0x04, 0x00}
	frame := tpkt(append(cotpDT(), s7Job(param)...))
	msg, _ := newReader().parseTPKTMessage(frame)
	if msg == nil {
		t.Fatal("expected a parsed message")
	}
	if msg.PayloadObscured {
		t.Error("classic S7comm must not be flagged PayloadObscured")
	}
}

func TestGetS7PlusOpcodeName(t *testing.T) {
	cases := map[int]string{
		s7PlusOpcodeRequest:      "Request",
		s7PlusOpcodeResponse:     "Response",
		s7PlusOpcodeNotification: "Notification",
		0x99:                     "Unknown",
	}
	for op, want := range cases {
		if got := getS7PlusOpcodeName(op); got != want {
			t.Errorf("getS7PlusOpcodeName(%#x) = %q, want %q", op, got, want)
		}
	}
}

func TestExtractPIServiceName(t *testing.T) {
	tests := []struct {
		name string
		in   []byte
		want string
	}{
		{"cold restart", []byte{0x00, 0x00, 'P', '_', 'P', 'R', 'O', 'G', 'R', 'A', 'M'}, "P_PROGRAM"},
		{"warm restart", []byte("\x00\x00_INSE\x00"), "_INSE"},
		{"too short", []byte{'A', 'B'}, ""},
		{"empty", nil, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := extractPIServiceName(tt.in); got != tt.want {
				t.Errorf("extractPIServiceName() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestHelperNameLookups(t *testing.T) {
	if getFunctionName(S7FuncWriteVar) != "Write Var" {
		t.Error("getFunctionName WriteVar")
	}
	if getAreaName(S7AreaDB) != "DataBlock (DB)" {
		t.Error("getAreaName DB")
	}
	if getMessageTypeName(S7CommMsgTypeUserData) != "UserData" {
		t.Error("getMessageTypeName UserData")
	}
	if getReturnCodeName(S7ReturnCodeSuccess) != "Success" {
		t.Error("getReturnCodeName Success")
	}
	if getPIServiceName(S7PIServiceWarmRestart) != "Warm Restart (_INSE)" {
		t.Error("getPIServiceName warm")
	}
}
